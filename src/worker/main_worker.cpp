/**
 * @file main_worker.cpp
 * @brief Proceso trabajador aislado: analiza el contenido de UN archivo y escribe el resultado en JSON.
 * @details Lo lanza IsolatedScanner con token restringido, integridad baja y dentro de un Job Object.
 *          Recibe un HANDLE de solo lectura heredado (--handle), por lo que no necesita acceso al sistema
 *          de archivos. No abre bases de datos ni verifica firmas: solo hashes, YARA y estructura del contenido.
 *
 *          Siempre responde con JSON, incluso ante un error (campo "error"), para que el servicio pueda
 *          diagnosticar. Códigos de salida: 0 = análisis correcto, 2 = argumentos, 3 = error controlado.
 */

#include "openguard/content_analysis.h"
#include "openguard/paths.h"
#include "openguard/yara_lite.h"

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
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

/// Responde con un error estructurado y devuelve el código de salida 3.
int fail(HANDLE out, const std::string& message) {
    openguard::ContentAnalysis a;
    a.ok = false;
    a.error = message;
    if (out && out != INVALID_HANDLE_VALUE) writeAll(out, openguard::contentAnalysisToJson(a));
    return 3;
}

/// Reduce los privilegios del propio proceso ANTES de analizar datos no confiables. Funciona aunque el servicio
/// no haya podido crear un token restringido (modo degradado, p. ej. cuando lo lanza una GUI elevada):
///  - integridad BAJA (no puede escribir en objetos de nivel medio/alto),
///  - todos los privilegios eliminados de forma permanente,
///  - sin creación de procesos hijos.
/// Los fallos se ignoran a propósito: son capas adicionales y el Job Object del llamador sigue aplicando.
void selfSandbox() {
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        PSID lowSid = nullptr;
        if (ConvertStringSidToSidW(L"S-1-16-4096", &lowSid)) {
            TOKEN_MANDATORY_LABEL tml{};
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = lowSid;
            SetTokenInformation(token, TokenIntegrityLevel, &tml, static_cast<DWORD>(sizeof(tml)) + GetLengthSid(lowSid));
            LocalFree(lowSid);
        }

        DWORD len = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
        if (len > 0) {
            std::vector<BYTE> buf(len);
            if (GetTokenInformation(token, TokenPrivileges, buf.data(), len, &len)) {
                auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
                for (DWORD i = 0; i < tp->PrivilegeCount; ++i) tp->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
                AdjustTokenPrivileges(token, FALSE, tp, 0, nullptr, nullptr);
            }
        }
        CloseHandle(token);
    }

    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child{};
    child.NoChildProcessCreation = 1;
    SetProcessMitigationPolicy(ProcessChildProcessPolicy, &child, sizeof(child));
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

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        fail(out, "argumento --handle invalido");
        return 2;
    }
    if (!out || out == INVALID_HANDLE_VALUE) return 2;

    try {
        // 1. Leer el contenido desde el handle heredado (antes de reducir privilegios, para no depender de él después)
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(hFile, &size) || size.QuadPart < 0) {
            return fail(out, "GetFileSizeEx fallo (codigo " + std::to_string(GetLastError()) + ")");
        }
        if (static_cast<uint64_t>(size.QuadPart) > kMaxBytes) return fail(out, "archivo demasiado grande");

        std::vector<uint8_t> data(static_cast<size_t>(size.QuadPart));
        size_t done = 0;
        while (done < data.size()) {
            DWORD got = 0;
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - done, 16u * 1024u * 1024u));
            if (!ReadFile(hFile, data.data() + done, chunk, &got, nullptr) || got == 0) {
                return fail(out, "ReadFile fallo (codigo " + std::to_string(GetLastError()) + ")");
            }
            done += got;
        }

        // 2. Cargar reglas YARA (solo lectura) y reducir privilegios ANTES de procesar el contenido no confiable
        openguard::YaraLite yara;
        yara.loadDirectories(openguard::paths::signaturesDir() / "yara_rules", openguard::paths::rulesUpdateDir());

        selfSandbox();

        // 3. Análisis. La extensión determina el tipo; la ruta real no se pasa al trabajador
        const std::filesystem::path pseudoPath(std::string("archivo") + ext);
        const openguard::ContentAnalysis analysis = openguard::analyzeContent(data, pseudoPath, &yara);

        return writeAll(out, openguard::contentAnalysisToJson(analysis)) ? 0 : 3;
    } catch (const std::exception& e) {
        return fail(out, std::string("excepcion: ") + e.what());
    } catch (...) {
        return fail(out, "excepcion desconocida");
    }
}
