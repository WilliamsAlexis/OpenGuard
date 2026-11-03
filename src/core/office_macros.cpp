/**
 * @file office_macros.cpp
 * @brief Implementación de la detección estática de macros de Office.
 */

#include "openguard/office_macros.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>
#include <unordered_set>

namespace openguard {

namespace {

constexpr size_t kMaxInspectBytes = 8 * 1024 * 1024;

constexpr std::array<uint8_t, 8> kOleMagic = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};

const std::unordered_set<std::string> kOleExt = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".pps", ".xla", ".ppa"};
const std::unordered_set<std::string> kMacroOoxmlExt = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppsm", ".ppam"};
const std::unordered_set<std::string> kPlainOoxmlExt = {".docx", ".dotx", ".xlsx", ".xltx", ".pptx", ".potx", ".ppsx"};

// Disparadores de ejecución automática al abrir/cerrar el documento
const char* const kAutoExec[] = {"autoopen", "autoexec", "autoclose", "auto_open", "auto_close", "document_open",
                                 "document_close", "workbook_open", "workbook_beforeclose", "presentation_open"};

// Palabras clave típicas de droppers y ejecución de comandos desde macros (en minúsculas)
const char* const kSuspicious[] = {"wscript.shell", "shell(", "createobject", "urldownloadtofile", "powershell",
                                   "cmd.exe", "environ(", "msxml2.xmlhttp", "winhttp.winhttprequest", "adodb.stream",
                                   "scripting.filesystemobject", "regsvr32", "mshta", "bitsadmin", "certutil",
                                   "callbyname", "virtualalloc", "rtlmovememory"};

std::string toLowerCopy(const uint8_t* data, size_t n) {
    std::string s(reinterpret_cast<const char*>(data), n);
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

/// Cadena ASCII -> UTF-16LE (los nombres de almacenamiento OLE y muchas cadenas de VBA están en UTF-16).
std::string widen(std::string_view ascii) {
    std::string w;
    w.reserve(ascii.size() * 2);
    for (char c : ascii) { w.push_back(c); w.push_back('\0'); }
    return w;
}

bool containsEither(const std::string& hay, std::string_view needleLower) {
    if (hay.find(needleLower) != std::string::npos) return true;
    return hay.find(widen(needleLower)) != std::string::npos;
}

} // namespace

bool isOfficeExtension(const std::string& e) {
    return kOleExt.count(e) || kMacroOoxmlExt.count(e) || kPlainOoxmlExt.count(e);
}

MacroReport analyzeOfficeMacros(const uint8_t* data, size_t size, const std::string& ext) {
    MacroReport r;
    if (!data || size < 8 || !isOfficeExtension(ext)) return r;
    r.isOfficeFormat = true;

    const size_t n = std::min(size, kMaxInspectBytes);
    const bool isOle = std::equal(kOleMagic.begin(), kOleMagic.end(), data);
    const bool isZip = data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04;
    const std::string lower = toLowerCopy(data, n);

    if (isOle) {
        // Un proyecto VBA aparece como almacenamiento/flujo "_VBA_PROJECT" en el directorio OLE
        if (containsEither(lower, "_vba_project")) r.hasMacros = true;
    } else if (isZip) {
        // La entrada vbaProject.bin figura con su nombre sin comprimir en las cabeceras del ZIP
        if (lower.find("vbaproject.bin") != std::string::npos) r.hasMacros = true;
    }

    if (!r.hasMacros) return r;

    r.score += 20;
    r.findings.push_back("El documento contiene macros VBA");

    // Un documento "sin macros" (.docx, .xlsx...) con proyecto VBA o un .doc/.xls con contenedor ZIP es incoherente
    if (kPlainOoxmlExt.count(ext)) {
        r.score += 25;
        r.findings.push_back("Extension sin macros (" + ext + ") pero con proyecto VBA incrustado: posible camuflaje");
    }

    // En OLE el texto de VBA es visible de forma parcial; en OOXML va comprimido y solo se conserva la presencia
    if (isOle) {
        for (const char* kw : kAutoExec) {
            if (containsEither(lower, kw)) {
                r.autoExec = true;
                r.findings.push_back(std::string("Se ejecuta automaticamente al abrir/cerrar (") + kw + ")");
                break;
            }
        }
        if (r.autoExec) r.score += 25;

        int hits = 0;
        for (const char* kw : kSuspicious) {
            if (containsEither(lower, kw)) {
                r.suspicious.emplace_back(kw);
                ++hits;
            }
        }
        if (hits > 0) {
            r.score += std::min(30, hits * 10);
            r.findings.push_back("Palabras clave sospechosas en macros (" + std::to_string(hits) + ")");
        }
    }

    r.score = std::min(r.score, 100);
    return r;
}

} // namespace openguard
