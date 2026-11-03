/**
 * @file realtime_monitor.h
 * @brief Monitor del sistema de archivos en tiempo real basado en ReadDirectoryChangesW.
 * @details Observa de forma recursiva un conjunto de directorios y notifica los archivos creados,
 *          modificados o renombrados una vez que dejan de recibir cambios (debounce), de modo que
 *          el escáner analice archivos completos y no escrituras parciales.
 *
 *          Nota de diseño: opera en modo usuario (post-operación). Notifica DESPUÉS de que el archivo
 *          fue escrito; no puede bloquear la ejecución previa como lo haría un minifilter (ver ROADMAP.md).
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace openguard {

/**
 * @class RealtimeMonitor
 * @brief Vigila directorios y despacha eventos de archivo con debounce.
 */
class RealtimeMonitor {
public:
    /// Callback invocado desde un hilo interno por cada ruta que cambió y se estabilizó.
    using Callback = std::function<void(const std::filesystem::path&)>;

    /**
     * @param quietPeriod Tiempo sin nuevos cambios tras el cual un archivo se considera estable.
     */
    explicit RealtimeMonitor(std::chrono::milliseconds quietPeriod = std::chrono::milliseconds(750));
    ~RealtimeMonitor();

    RealtimeMonitor(const RealtimeMonitor&) = delete;
    RealtimeMonitor& operator=(const RealtimeMonitor&) = delete;

    /**
     * @brief Inicia la vigilancia de los directorios indicados (recursiva).
     * @param directories Directorios a observar; los inexistentes o inaccesibles se omiten.
     * @param onFileChanged Función a invocar por cada archivo estable. Debe capturar sus propias excepciones.
     * @return true si al menos un directorio pudo vigilarse.
     */
    bool start(const std::vector<std::filesystem::path>& directories, Callback onFileChanged);

    /// Detiene la vigilancia y espera la finalización de todos los hilos. Es idempotente.
    void stop();

    /// Indica si el monitor está activo.
    [[nodiscard]] bool isRunning() const noexcept { return m_running; }

    /// Cantidad de directorios que se están vigilando realmente.
    [[nodiscard]] size_t watchedCount() const noexcept { return m_watchedCount; }

private:
    void watchLoop(std::filesystem::path directory, void* directoryHandle);
    void dispatchLoop();
    void enqueue(const std::filesystem::path& path);

    std::chrono::milliseconds m_quietPeriod;
    Callback m_callback;

    void* m_stopEvent{nullptr};               ///< HANDLE de evento manual para detener hilos de vigilancia.
    std::vector<std::thread> m_watchThreads;
    std::thread m_dispatchThread;

    std::mutex m_queueMutex;
    std::condition_variable m_queueCv;
    std::map<std::filesystem::path, std::chrono::steady_clock::time_point> m_pending;

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopRequested{false};
    std::atomic<size_t> m_watchedCount{0};
};

} // namespace openguard
