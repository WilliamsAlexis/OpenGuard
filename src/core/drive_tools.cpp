/**
 * @file drive_tools.cpp
 * @brief Implementación de la inspección y reparación de unidades externas.
 */

#include "openguard/drive_tools.h"
#include "openguard/paths.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <fstream>
#include <unordered_set>

namespace openguard {

namespace {

namespace fs = std::filesystem;

std::wstring lowerW(std::wstring s) {
    for (auto& c : s) c = static_cast<wchar_t>(std::towlower(c));
    return s;
}

/// Carpetas y archivos propios del sistema que son legítimamente ocultos: no se tocan.
bool isProtectedName(const std::wstring& lowerName) {
    static const std::unordered_set<std::wstring> kProtected = {
        L"system volume information", L"$recycle.bin", L"recycler", L"recycled", L"found.000", L"msocache",
        L"thumbs.db", L"desktop.ini", L"$winreagent", L"config.msi", L"boot", L"bootmgr", L"efi",
        L"hiberfil.sys", L"pagefile.sys", L"swapfile.sys", L"autorun.inf", L"documents and settings", L"recovery"};
    return kProtected.count(lowerName) > 0;
}

bool isHiddenOrSystem(const fs::path& p) {
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;
}

bool isDirectoryPath(const fs::path& p) {
    const DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

/// Lee hasta `maxBytes` del archivo para búsquedas de texto (nunca se ejecuta).
std::string readHead(const fs::path& p, size_t maxBytes) {
    std::ifstream in(p, std::ios::binary);
    if (!in.is_open()) return {};
    std::string s(maxBytes, '\0');
    in.read(s.data(), static_cast<std::streamsize>(maxBytes));
    s.resize(static_cast<size_t>(in.gcount()));
    return s;
}

std::string lowerA(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

/// Un acceso directo es sospechoso si invoca un intérprete o un script (se mira ASCII y UTF-16).
bool lnkLooksMalicious(const fs::path& lnk) {
    const std::string data = lowerA(readHead(lnk, 64 * 1024));
    if (data.empty()) return false;

    auto has = [&data](const char* needle) {
        if (data.find(needle) != std::string::npos) return true;
        std::string wide;
        for (const char* p = needle; *p; ++p) { wide.push_back(*p); wide.push_back('\0'); }
        return data.find(wide) != std::string::npos;
    };
    return has("cmd.exe") || has("wscript") || has("cscript") || has("powershell") || has("mshta") ||
           has(".vbs") || has(".js") || has("\\recycler") || has("$recycle.bin") || has("rundll32");
}

} // namespace

DriveInspection inspectDrive(const fs::path& root) {
    DriveInspection r;
    r.root = root;

    std::error_code ec;
    if (!fs::is_directory(root, ec)) return r;

    struct Entry { fs::path path; std::wstring lowerName; std::wstring lowerStem; bool isDir; bool hidden; };
    std::vector<Entry> entries;

    for (fs::directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec)) {
        Entry e;
        e.path = it->path();
        e.lowerName = lowerW(e.path.filename().wstring());
        e.lowerStem = lowerW(e.path.stem().wstring());
        e.isDir = isDirectoryPath(e.path);
        e.hidden = isHiddenOrSystem(e.path);
        entries.push_back(std::move(e));
        if (entries.size() > 5000) break; // raíces enormes: se inspeccionan las primeras
    }

    std::unordered_set<std::wstring> hiddenDirStems;
    for (const auto& e : entries) {
        if (e.isDir && e.hidden && !isProtectedName(e.lowerName)) hiddenDirStems.insert(e.lowerName);
    }
    std::unordered_set<std::wstring> dirNames;
    for (const auto& e : entries) if (e.isDir) dirNames.insert(e.lowerName);

    for (const auto& e : entries) {
        // 1. autorun.inf que lanza programas
        if (e.lowerName == L"autorun.inf" && !e.isDir) {
            const std::string content = lowerA(readHead(e.path, 4096));
            if (content.find("open=") != std::string::npos || content.find("shellexecute=") != std::string::npos ||
                content.find("shell\\open\\command") != std::string::npos || content.find("shell\\explore\\command") != std::string::npos) {
                r.hasAutorun = true;
                r.findings.push_back({"autorun", "autorun.inf que ejecuta un programa al conectar la unidad", e.path});
            }
            continue;
        }

        // 2. Accesos directos en la raíz
        if (!e.isDir && lowerW(e.path.extension().wstring()) == L".lnk") {
            if (hiddenDirStems.count(e.lowerStem)) {
                r.shortcutVirusSuspected = true;
                r.findings.push_back({"shortcut_virus", "Acceso directo que reemplaza a la carpeta oculta \"" +
                                                           paths::toUtf8(e.path.stem()) + "\"", e.path});
            } else if (lnkLooksMalicious(e.path)) {
                r.shortcutVirusSuspected = true;
                r.findings.push_back({"lnk_suspicious", "Acceso directo que invoca un interprete de comandos o script", e.path});
            }
            continue;
        }

        // 3. Ejecutables con el nombre de una carpeta (suplantan a la carpeta)
        if (!e.isDir && lowerW(e.path.extension().wstring()) == L".exe" && dirNames.count(e.lowerStem)) {
            r.shortcutVirusSuspected = true;
            r.findings.push_back({"exe_lookalike", "Ejecutable con el mismo nombre que la carpeta \"" +
                                                       paths::toUtf8(e.path.stem()) + "\" (la suplanta)", e.path});
            continue;
        }

        // 4. Elementos ocultos del usuario
        if (e.hidden && !isProtectedName(e.lowerName)) {
            ++r.hiddenItems;
            r.findings.push_back({"hidden", "Elemento oculto: " + paths::toUtf8(e.path.filename()), e.path});
        }
    }

    // Ocultar elementos es normal en algunas unidades; solo se ofrece restaurarlos si hay otros síntomas de ocultación
    // o si son muchos (ocultar todo es el comportamiento de estos virus).
    if (!r.shortcutVirusSuspected && r.hiddenItems < 3) {
        r.findings.erase(std::remove_if(r.findings.begin(), r.findings.end(),
                                        [](const DriveFinding& f) { return f.code == "hidden"; }),
                         r.findings.end());
        r.hiddenItems = 0;
    }
    return r;
}

RepairResult repairDrive(const DriveInspection& inspection) {
    RepairResult res;
    std::error_code ec;

    for (const auto& f : inspection.findings) {
        if (f.code == "autorun" || f.code == "shortcut_virus" || f.code == "lnk_suspicious") {
            SetFileAttributesW(f.path.c_str(), FILE_ATTRIBUTE_NORMAL); // quitar solo-lectura/oculto antes de borrar
            if (fs::remove(f.path, ec) && !ec) {
                if (f.code == "autorun") ++res.removedAutorun; else ++res.removedShortcuts;
                res.log.push_back("Eliminado: " + paths::toUtf8(f.path.filename()));
            } else {
                ++res.failed;
                res.log.push_back("No se pudo eliminar: " + paths::toUtf8(f.path.filename()));
            }
        } else if (f.code == "hidden") {
            const DWORD a = GetFileAttributesW(f.path.c_str());
            if (a != INVALID_FILE_ATTRIBUTES &&
                SetFileAttributesW(f.path.c_str(), a & ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) {
                ++res.unhidden;
                res.log.push_back("Visible de nuevo: " + paths::toUtf8(f.path.filename()));
            } else {
                ++res.failed;
                res.log.push_back("No se pudo mostrar: " + paths::toUtf8(f.path.filename()));
            }
        }
        // exe_lookalike: no se borra aquí (podría ser legítimo): lo evalúa el análisis y se aísla si es amenaza
    }
    return res;
}

} // namespace openguard
