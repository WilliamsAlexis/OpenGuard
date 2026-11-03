/**
 * @file paths.cpp
 * @brief Implementación de la resolución de rutas de OpenGuard.
 */

#include "openguard/paths.h"

#include <windows.h>

#include <vector>

namespace openguard::paths {

namespace {

std::wstring getEnv(const wchar_t* name) {
    DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) return {};
    std::wstring value(size, L'\0');
    DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    value.resize(written);
    return value;
}

} // namespace

std::string toUtf8(const std::filesystem::path& p) {
    const std::wstring wide = p.wstring();
    if (wide.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                        out.data(), len, nullptr, nullptr);
    return out;
}

std::filesystem::path fromUtf8(const std::string& s) {
    if (s.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (len <= 0) return {};
    std::wstring wide(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), wide.data(), len);
    return std::filesystem::path(wide);
}

std::filesystem::path executableDir() {
    std::vector<wchar_t> buf(MAX_PATH);
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) return std::filesystem::current_path();
        if (n < buf.size()) {
            return std::filesystem::path(std::wstring(buf.data(), n)).parent_path();
        }
        buf.resize(buf.size() * 2); // Ruta larga: reintentar con un búfer mayor
    }
}

std::filesystem::path dataDir() {
    std::filesystem::path dir;

    const std::wstring overrideDir = getEnv(L"OPENGUARD_DATA_DIR");
    if (!overrideDir.empty()) {
        dir = overrideDir;
    } else {
        const std::wstring programData = getEnv(L"ProgramData");
        dir = programData.empty() ? (executableDir() / "data")
                                  : (std::filesystem::path(programData) / "OpenGuard");
    }

    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

std::filesystem::path signaturesDir() {
    // 1. Instalación normal: <ejecutable>\signatures
    std::filesystem::path candidate = executableDir() / "signatures";
    std::error_code ec;
    if (std::filesystem::exists(candidate / "hashes_index.json", ec)) return candidate;

    // 2. Entorno de desarrollo: ejecutable en build\...\Release, recursos en la raíz del repositorio
    std::filesystem::path probe = executableDir();
    for (int i = 0; i < 6 && probe.has_parent_path() && probe != probe.parent_path(); ++i) {
        probe = probe.parent_path();
        if (std::filesystem::exists(probe / "signatures" / "hashes_index.json", ec)) {
            return probe / "signatures";
        }
    }
    return candidate;
}

std::filesystem::path databasePath() {
    return dataDir() / "hashes.db";
}

std::filesystem::path quarantineDir() {
    return dataDir() / "quarantine";
}

std::filesystem::path logsDir() {
    std::filesystem::path dir = dataDir() / "logs";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

} // namespace openguard::paths

namespace openguard::paths {

std::string extensionLower(const std::filesystem::path& p) {
    const std::wstring ext = p.extension().wstring();
    std::string out;
    out.reserve(ext.size());
    for (wchar_t c : ext) {
        if (c >= L'A' && c <= L'Z') out.push_back(static_cast<char>(c - L'A' + 'a'));
        else if (c < 0x80) out.push_back(static_cast<char>(c));
        else out.push_back('?');
    }
    return out;
}

} // namespace openguard::paths
