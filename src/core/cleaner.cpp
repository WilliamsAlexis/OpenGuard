/**
 * @file cleaner.cpp
 * @brief Implementación de la limpieza de archivos temporales.
 */

#include "openguard/cleaner.h"

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cwctype>
#include <cstdio>

#pragma comment(lib, "shell32.lib")

namespace openguard::cleaner {

namespace fs = std::filesystem;

namespace {

constexpr int kMaxDepth = 48;

bool cancelled(const std::atomic<bool>* c) { return c && c->load(); }

bool oldEnough(const fs::path& p, std::chrono::hours minAge) {
    if (minAge.count() <= 0) return true;
    std::error_code ec;
    const auto t = fs::last_write_time(p, ec);
    if (ec) return false;
    return (fs::file_time_type::clock::now() - t) >= minAge;
}

bool startsWithNoCase(const std::wstring& s, const std::wstring& prefix) {
    if (prefix.empty()) return true;
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::towlower(s[i]) != std::towlower(prefix[i])) return false;
    }
    return true;
}

/// Recorre una carpeta sin seguir enlaces ni uniones. `onFile` recibe cada archivo; `onDirDone` cada subcarpeta ya recorrida.
template <class FileFn, class DirFn>
void walk(const fs::path& dir, int depth, const std::atomic<bool>* cancel, FileFn& onFile, DirFn& onDirDone) {
    if (depth > kMaxDepth || cancelled(cancel)) return;
    std::error_code ec;
    fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
    if (ec) return;
    for (; !ec && it != fs::directory_iterator(); it.increment(ec)) {
        if (cancelled(cancel)) return;
        const fs::path p = it->path();
        const DWORD attr = GetFileAttributesW(p.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        if (attr & FILE_ATTRIBUTE_REPARSE_POINT) continue; // enlaces y uniones: nunca se siguen ni se tocan
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            walk(p, depth + 1, cancel, onFile, onDirDone);
            onDirDone(p);
        } else {
            onFile(p);
        }
    }
}

bool safeRoot(const fs::path& root) {
    if (root.empty() || !root.has_relative_path()) return false; // vacía o raíz de unidad
    std::error_code ec;
    return fs::is_directory(root, ec);
}

fs::path envPath(const wchar_t* name) {
    wchar_t buf[MAX_PATH * 2]{};
    const DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
    return (n > 0 && n < std::size(buf)) ? fs::path(std::wstring(buf, n)) : fs::path{};
}

} // namespace

Usage measureDirectory(const fs::path& root, std::chrono::hours minAge, const std::wstring& namePrefix, const std::atomic<bool>* cancel) {
    Usage u;
    if (!safeRoot(root)) return u;
    auto onFile = [&](const fs::path& p) {
        if (!startsWithNoCase(p.filename().wstring(), namePrefix) || !oldEnough(p, minAge)) return;
        std::error_code ec;
        const auto size = fs::file_size(p, ec);
        if (ec) return;
        ++u.files;
        u.bytes += size;
    };
    auto onDir = [](const fs::path&) {};
    walk(root, 0, cancel, onFile, onDir);
    return u;
}

CleanResult cleanDirectory(const fs::path& root, std::chrono::hours minAge, const std::wstring& namePrefix, const std::atomic<bool>* cancel) {
    CleanResult r;
    if (!safeRoot(root)) return r;
    auto onFile = [&](const fs::path& p) {
        if (!startsWithNoCase(p.filename().wstring(), namePrefix) || !oldEnough(p, minAge)) return;
        std::error_code ec;
        const auto size = fs::file_size(p, ec);
        SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_NORMAL); // los de solo lectura tambien se pueden borrar
        if (DeleteFileW(p.c_str())) {
            ++r.deleted;
            r.freed += ec ? 0 : size;
        } else {
            ++r.failed; // en uso o sin permisos
        }
    };
    auto onDir = [&](const fs::path& d) {
        RemoveDirectoryW(d.c_str()); // solo tiene exito si quedo vacia
    };
    walk(root, 0, cancel, onFile, onDir);
    return r;
}

std::vector<Category> categories() {
    std::vector<Category> out;
    std::error_code ec;
    const fs::path local = envPath(L"LOCALAPPDATA");
    const fs::path win = envPath(L"SystemRoot");
    const fs::path progData = envPath(L"ProgramData");

    {
        Category c;
        c.id = "user_temp";
        c.name = L"Archivos temporales del usuario";
        c.description = L"Carpeta Temp de su cuenta. Solo archivos con mas de un dia sin modificar; los que estan en uso se respetan.";
        c.roots.push_back(envPath(L"TEMP"));
        c.minAge = std::chrono::hours(24);
        if (safeRoot(c.roots[0])) out.push_back(std::move(c));
    }
    if (!win.empty()) {
        Category c;
        c.id = "windows_temp";
        c.name = L"Archivos temporales de Windows";
        c.description = L"Carpeta Windows\\Temp. Solo archivos con mas de un dia sin modificar.";
        c.roots.push_back(win / L"Temp");
        c.minAge = std::chrono::hours(24);
        if (safeRoot(c.roots[0])) out.push_back(std::move(c));
    }
    if (!local.empty()) {
        Category c;
        c.id = "thumbnails";
        c.name = L"Cache de miniaturas";
        c.description = L"Miniaturas de imagenes y videos que el Explorador vuelve a generar cuando las necesita.";
        c.roots.push_back(local / L"Microsoft" / L"Windows" / L"Explorer");
        c.namePrefix = L"thumbcache_";
        if (safeRoot(c.roots[0])) out.push_back(std::move(c));
    }
    {
        Category c;
        c.id = "crash_dumps";
        c.name = L"Informes de errores y volcados";
        c.description = L"Volcados de memoria e informes de errores de Windows ya enviados o antiguos.";
        if (!local.empty()) c.roots.push_back(local / L"CrashDumps");
        if (!progData.empty()) {
            c.roots.push_back(progData / L"Microsoft" / L"Windows" / L"WER" / L"ReportArchive");
            c.roots.push_back(progData / L"Microsoft" / L"Windows" / L"WER" / L"ReportQueue");
        }
        std::vector<fs::path> existing;
        for (auto& r : c.roots) if (safeRoot(r)) existing.push_back(r);
        c.roots = std::move(existing);
        if (!c.roots.empty()) out.push_back(std::move(c));
    }
    if (!local.empty()) {
        Category c;
        c.id = "browser_cache";
        c.name = L"Cache de navegadores (Chrome y Edge)";
        c.description = L"Solo la cache de paginas, no sus contrasenas, historial ni sesiones. Las webs pueden tardar un poco mas en cargar la primera vez.";
        c.defaultSelected = false;
        const fs::path roots[] = {local / L"Google" / L"Chrome" / L"User Data" / L"Default",
                                  local / L"Microsoft" / L"Edge" / L"User Data" / L"Default"};
        for (const auto& base : roots) {
            for (const wchar_t* sub : {L"Cache", L"Code Cache", L"GPUCache"}) {
                if (safeRoot(base / sub)) c.roots.push_back(base / sub);
            }
        }
        if (!c.roots.empty()) out.push_back(std::move(c));
    }
    {
        Category c;
        c.id = "recycle_bin";
        c.name = L"Papelera de reciclaje";
        c.description = L"Vacia la Papelera de todas las unidades. Lo que contiene no se podra recuperar.";
        c.defaultSelected = false;
        c.recycleBin = true;
        out.push_back(std::move(c));
    }
    return out;
}

Usage measure(const Category& c, const std::atomic<bool>* cancel) {
    Usage u;
    if (c.recycleBin) {
        SHQUERYRBINFO info{};
        info.cbSize = sizeof(info);
        if (SUCCEEDED(SHQueryRecycleBinW(nullptr, &info))) {
            u.files = static_cast<size_t>(info.i64NumItems);
            u.bytes = static_cast<uint64_t>(info.i64Size);
        }
        return u;
    }
    for (const auto& root : c.roots) {
        const Usage x = measureDirectory(root, c.minAge, c.namePrefix, cancel);
        u.files += x.files;
        u.bytes += x.bytes;
    }
    return u;
}

CleanResult clean(const Category& c, const std::atomic<bool>* cancel) {
    CleanResult r;
    if (c.recycleBin) {
        const Usage before = measure(c);
        if (SUCCEEDED(SHEmptyRecycleBinW(nullptr, nullptr, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND))) {
            r.deleted = before.files;
            r.freed = before.bytes;
        } else {
            r.failed = before.files;
        }
        return r;
    }
    for (const auto& root : c.roots) {
        const CleanResult x = cleanDirectory(root, c.minAge, c.namePrefix, cancel);
        r.deleted += x.deleted;
        r.freed += x.freed;
        r.failed += x.failed;
    }
    return r;
}

std::wstring formatBytes(uint64_t bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double v = static_cast<double>(bytes);
    size_t u = 0;
    while (v >= 1024.0 && u + 1 < std::size(units)) { v /= 1024.0; ++u; }
    wchar_t buf[48];
    if (u == 0) swprintf(buf, std::size(buf), L"%llu B", static_cast<unsigned long long>(bytes));
    else swprintf(buf, std::size(buf), L"%.1f %ls", v, units[u]);
    return buf;
}

} // namespace openguard::cleaner
