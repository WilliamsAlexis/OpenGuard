/**
 * @file main_worker.cpp
 * @brief Proceso trabajador aislado: analiza el contenido de UN archivo y escribe el resultado en JSON.
 * @details Lo lanza IsolatedScanner con token restringido, integridad baja y dentro de un Job Object.
 *          Recibe un HANDLE de solo lectura heredado (--handle), por lo que no necesita acceso al sistema
 *          de archivos. No abre bases de datos ni verifica firmas: solo hashes, YARA y estructura del contenido.
 *          Códigos de salida: 0 = correcto, 2 = argumentos, 3 = error de lectura/memoria.
 */

#include "openguard/content_analysis.h"
#include "openguard/paths.h"
#include "openguard/yara_lite.h"

#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kMaxBytes = 256ull * 1024ull * 1024ull;

bool writeAll(HANDLE out, const std::string& s) {
    size_t done = 0;
    while (done < s.size()) {
        DWORD written = 0;
        if (!WriteFile(out, s.data() + done, static_cast<DWORD>(std::min<size_t>(s.size() - done, 1u << 20)), &written, nullptr) ||
            written == 0) return false;
        done += written;
    }
    return true;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    HANDLE hFile = nullptr;
    std::string ext;

    for (int i = 1; i + 1 < argc; i += 2) {
        const std::wstring key = argv[i];
        const std::wstring val = argv[i + 1];
        if (key == L"--handle") {
            hFile = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(std::wcstoull(val.c_str(), nullptr, 16)));
        } else if (key == L"--ext") {
            for (wchar_t c : val) ext.push_back(c < 0x80 ? static_cast<char>(c) : '?');
        }
    }
    if (!hFile || hFile == INVALID_HANDLE_VALUE) return 2;

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE) return 2;

    // Leer todo el contenido desde el handle heredado
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(hFile, &size) || size.QuadPart < 0 || static_cast<uint64_t>(size.QuadPart) > kMaxBytes) return 3;

    std::vector<uint8_t> data;
    try {
        data.resize(static_cast<size_t>(size.QuadPart));
    } catch (...) {
        return 3;
    }
    size_t done = 0;
    while (done < data.size()) {
        DWORD got = 0;
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - done, 16u * 1024u * 1024u));
        if (!ReadFile(hFile, data.data() + done, chunk, &got, nullptr) || got == 0) return 3;
        done += got;
    }

    // Reglas YARA (solo lectura desde la carpeta de instalación)
    openguard::YaraLite yara;
    yara.loadDirectory(openguard::paths::signaturesDir() / "yara_rules");

    // La extensión determina el tipo de análisis; la ruta real no se pasa al trabajador
    const std::filesystem::path pseudoPath(std::string("archivo") + ext);
    openguard::ContentAnalysis analysis;
    try {
        analysis = openguard::analyzeContent(data, pseudoPath, &yara);
    } catch (const std::exception& e) {
        analysis.ok = false;
        analysis.error = e.what();
    }

    return writeAll(out, openguard::contentAnalysisToJson(analysis)) ? 0 : 3;
}
