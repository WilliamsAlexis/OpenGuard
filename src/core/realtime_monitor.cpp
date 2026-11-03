/**
 * @file realtime_monitor.cpp
 * @brief Implementación del monitor de archivos en tiempo real (ReadDirectoryChangesW overlapped).
 */

#include "openguard/realtime_monitor.h"

#include <windows.h>

#include <algorithm>

namespace openguard {

namespace {

constexpr DWORD kNotifyFilter =
    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE;

constexpr size_t kBufferDwords = 16 * 1024; // 64 KB, alineado a DWORD como exige la API

} // namespace

RealtimeMonitor::RealtimeMonitor(std::chrono::milliseconds quietPeriod)
    : m_quietPeriod(quietPeriod) {}

RealtimeMonitor::~RealtimeMonitor() {
    stop();
}

bool RealtimeMonitor::start(const std::vector<std::filesystem::path>& directories, Callback onFileChanged) {
    if (m_running || !onFileChanged) return false;

    m_callback = std::move(onFileChanged);
    m_stopRequested = false;
    m_watchedCount = 0;

    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent) return false;
    m_stopEvent = stopEvent;

    for (const auto& dir : directories) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) continue;

        HANDLE hDir = CreateFileW(
            dir.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr
        );
        if (hDir == INVALID_HANDLE_VALUE) continue;

        ++m_watchedCount;
        m_watchThreads.emplace_back(&RealtimeMonitor::watchLoop, this, dir, static_cast<void*>(hDir));
    }

    if (m_watchedCount == 0) {
        CloseHandle(stopEvent);
        m_stopEvent = nullptr;
        return false;
    }

    m_running = true;
    m_dispatchThread = std::thread(&RealtimeMonitor::dispatchLoop, this);
    return true;
}

void RealtimeMonitor::stop() {
    if (!m_running.exchange(false)) return;

    m_stopRequested = true;
    if (m_stopEvent) SetEvent(static_cast<HANDLE>(m_stopEvent));
    m_queueCv.notify_all();

    for (auto& t : m_watchThreads) {
        if (t.joinable()) t.join();
    }
    m_watchThreads.clear();

    if (m_dispatchThread.joinable()) m_dispatchThread.join();

    if (m_stopEvent) {
        CloseHandle(static_cast<HANDLE>(m_stopEvent));
        m_stopEvent = nullptr;
    }

    std::lock_guard<std::mutex> lock(m_queueMutex);
    m_pending.clear();
    m_watchedCount = 0;
}

void RealtimeMonitor::enqueue(const std::filesystem::path& path) {
    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_pending[path] = std::chrono::steady_clock::now(); // Cada cambio reinicia el período de silencio
    }
    m_queueCv.notify_one();
}

void RealtimeMonitor::watchLoop(std::filesystem::path directory, void* directoryHandle) {
    HANDLE hDir = static_cast<HANDLE>(directoryHandle);
    HANDLE hStop = static_cast<HANDLE>(m_stopEvent);

    std::vector<DWORD> buffer(kBufferDwords);
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        CloseHandle(hDir);
        return;
    }

    while (!m_stopRequested) {
        ResetEvent(ov.hEvent);
        DWORD bytes = 0;
        if (!ReadDirectoryChangesW(hDir, buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(DWORD)),
                                   TRUE, kNotifyFilter, &bytes, &ov, nullptr)) {
            break; // El directorio dejó de ser accesible (desmontado, eliminado)
        }

        HANDLE waitHandles[2] = { ov.hEvent, hStop };
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

        if (waitResult != WAIT_OBJECT_0) {
            // Detención solicitada (o error de espera): cancelar la E/S pendiente y esperar su cierre
            CancelIoEx(hDir, &ov);
            GetOverlappedResult(hDir, &ov, &bytes, TRUE);
            break;
        }

        if (!GetOverlappedResult(hDir, &ov, &bytes, FALSE)) break;
        if (bytes == 0) continue; // Desbordamiento del búfer: se perdieron eventos, se reanuda la lectura

        const BYTE* cursor = reinterpret_cast<const BYTE*>(buffer.data());
        for (;;) {
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(cursor);

            if (info->Action == FILE_ACTION_ADDED ||
                info->Action == FILE_ACTION_MODIFIED ||
                info->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                const std::wstring name(info->FileName, info->FileNameLength / sizeof(WCHAR));
                enqueue(directory / name);
            }

            if (info->NextEntryOffset == 0) break;
            cursor += info->NextEntryOffset;
        }
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
}

void RealtimeMonitor::dispatchLoop() {
    while (!m_stopRequested) {
        std::vector<std::filesystem::path> ready;
        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_queueCv.wait_for(lock, std::chrono::milliseconds(250));
            if (m_stopRequested) break;

            const auto now = std::chrono::steady_clock::now();
            for (auto it = m_pending.begin(); it != m_pending.end();) {
                if (now - it->second >= m_quietPeriod) {
                    ready.push_back(it->first);
                    it = m_pending.erase(it);
                } else {
                    ++it;
                }
            }
        }

        for (const auto& path : ready) {
            if (m_stopRequested) break;
            try {
                m_callback(path);
            } catch (...) {
                // Un fallo al analizar un archivo no debe detener la vigilancia
            }
        }
    }
}

} // namespace openguard
