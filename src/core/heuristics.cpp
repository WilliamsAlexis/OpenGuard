/**
 * @file heuristics.cpp
 * @brief Implementación del motor unificado de heurísticas para ejecutables y scripts.
 * @details Este módulo implementa la detección de ofuscación de comandos, evasión de AMSI,
 *          cunas de descarga de malware y coordina el análisis estático de binarios PE.
 */

#include "openguard/heuristics.h"
#include "openguard/paths.h"

#include <fstream>
#include <algorithm>
#include <iterator>

namespace openguard {

namespace {

/**
 * @brief Convierte una cadena de caracteres a minúsculas estándar.
 * @param str Cadena de entrada.
 * @return Cadena en minúsculas.
 */
std::string toLowerString(std::string str) {
    for (char& c : str) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return str;
}

} // namespace anónimo

ScriptReport ScriptAnalyzer::analyze(const std::filesystem::path& filePath) {
    ScriptReport report;
    report.filePath = filePath;

    std::string ext = paths::extensionLower(filePath);

    if (ext == ".ps1" || ext == ".psm1" || ext == ".psd1") {
        report.scriptType = "PowerShell";
    } else if (ext == ".vbs" || ext == ".vbe" || ext == ".wsf") {
        report.scriptType = "VBScript";
    } else if (ext == ".js" || ext == ".jse") {
        report.scriptType = "JScript";
    } else if (ext == ".bat" || ext == ".cmd") {
        report.scriptType = "Batch";
    } else if (ext == ".hta") {
        report.scriptType = "HTA";
    } else {
        report.scriptType = "Generico";
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        report.filePath = filePath;
        report.scriptType = paths::extensionLower(filePath).empty() ? "Generico" : report.scriptType;
        return report;
    }

    // Lectura de hasta 512 KB para análisis estático de scripts (evita cargar archivos enormes en RAM)
    constexpr size_t kMaxScriptBytes = 512 * 1024;
    std::string content(kMaxScriptBytes, '\0');
    file.read(content.data(), static_cast<std::streamsize>(kMaxScriptBytes));
    content.resize(static_cast<size_t>(file.gcount()));
    file.close();

    return analyzeContent(std::move(content), filePath);
}

ScriptReport ScriptAnalyzer::analyzeContent(std::string content, const std::filesystem::path& filePath) {
    ScriptReport report;
    report.filePath = filePath;

    const std::string ext = paths::extensionLower(filePath);
    if (ext == ".ps1" || ext == ".psm1" || ext == ".psd1") {
        report.scriptType = "PowerShell";
    } else if (ext == ".vbs" || ext == ".vbe" || ext == ".wsf") {
        report.scriptType = "VBScript";
    } else if (ext == ".js" || ext == ".jse") {
        report.scriptType = "JScript";
    } else if (ext == ".bat" || ext == ".cmd") {
        report.scriptType = "Batch";
    } else if (ext == ".hta") {
        report.scriptType = "HTA";
    } else {
        report.scriptType = "Generico";
    }

    constexpr size_t kMaxScriptBytes = 512 * 1024;
    if (content.size() > kMaxScriptBytes) content.resize(kMaxScriptBytes);
    if (content.empty()) return report;

    // Entropía de caracteres en el script
    report.entropy = PEAnalyzer::calculateShannonEntropy(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    if (report.entropy > 5.8) {
        report.isObfuscated = true;
        report.addFinding("Entropia inusualmente alta en script (" +
                          std::to_string(report.entropy).substr(0, 4) + "), posible ofuscacion", 25);
    }

    std::string lowerContent = toLowerString(content);

    if (report.scriptType == "PowerShell") {
        analyzePowerShell(lowerContent, report);
    } else if (report.scriptType == "VBScript" || report.scriptType == "JScript" || report.scriptType == "HTA") {
        analyzeVbsJs(lowerContent, report);
    } else if (report.scriptType == "Batch") {
        analyzeBatch(lowerContent, report);
    }

    // Regla común: Eliminación de copias de seguridad de Windows (Ransomware)
    if (lowerContent.find("vssadmin") != std::string::npos &&
        lowerContent.find("delete") != std::string::npos &&
        lowerContent.find("shadows") != std::string::npos) {
        report.addFinding("Comando critico de destruccion de instantaneas de volumen (vssadmin delete shadows)", 75);
    }

    return report;
}

void ScriptAnalyzer::analyzePowerShell(const std::string& content, ScriptReport& report) {
    // 1. Detección de intentos de evasión de AMSI (Antimalware Scan Interface)
    if (content.find("amsiutils") != std::string::npos ||
        content.find("amsiinitfailed") != std::string::npos ||
        (content.find("[ref].assembly.gettype") != std::string::npos && content.find("nonpublic") != std::string::npos)) {
        report.addFinding("Intento deliberado de evasion de AMSI detectado en PowerShell", 85);
    }

    // 2. Detección de cunas de descarga (Download Cradles)
    if ((content.find("net.webclient") != std::string::npos || content.find("invoke-webrequest") != std::string::npos) &&
        (content.find("downloadstring") != std::string::npos || content.find("downloadfile") != std::string::npos)) {
        report.addFinding("Cuna de descarga sigilosa remota detectada (WebClient.DownloadString/File)", 45);
    }

    // 3. Ejecución directa en memoria (In-Memory Execution)
    if (content.find("invoke-expression") != std::string::npos ||
        content.find("iex(") != std::string::npos ||
        content.find("iex ") != std::string::npos) {
        report.addFinding("Invocacion de ejecucion en memoria dinamica (IEX / Invoke-Expression)", 35);
    }

    // 4. Parámetros de ejecución oculta y omisión de directivas
    if (content.find("-executionpolicy bypass") != std::string::npos ||
        content.find("-ep bypass") != std::string::npos) {
        report.addFinding("Omision de politicas de ejecucion de PowerShell (-ExecutionPolicy Bypass)", 20);
    }

    if (content.find("-windowstyle hidden") != std::string::npos ||
        content.find("-w hidden") != std::string::npos) {
        report.addFinding("Ejecucion con ventana oculta en segundo plano (-WindowStyle Hidden)", 20);
    }

    // 5. Ofuscación con comandos codificados en Base64
    if (content.find("-encodedcommand") != std::string::npos ||
        content.find("-enc ") != std::string::npos ||
        content.find("frombase64string") != std::string::npos) {
        report.isObfuscated = true;
        report.addFinding("Uso de comandos codificados en Base64 (-EncodedCommand)", 40);
    }

    // 6. Extracción de credenciales conocidas
    if (content.find("invoke-mimikatz") != std::string::npos ||
        content.find("sekurlsa") != std::string::npos ||
        content.find("lsadump") != std::string::npos) {
        report.addFinding("Herramienta de extraccion masiva de contraseñas (Mimikatz/Sekurlsa)", 90);
    }
}

void ScriptAnalyzer::analyzeVbsJs(const std::string& content, ScriptReport& report) {
    if (content.find("wscript.shell") != std::string::npos &&
        (content.find(".run") != std::string::npos || content.find(".exec") != std::string::npos)) {
        report.addFinding("Llamada de ejecucion de comandos del sistema operativo (WScript.Shell.Run)", 30);
    }

    if (content.find("adodb.stream") != std::string::npos && content.find("savetofile") != std::string::npos) {
        report.addFinding("Escritura binaria en disco mediante stream ActiveX (ADODB.Stream Dropper)", 45);
    }

    if (content.find("eval(") != std::string::npos ||
        content.find("unescape(") != std::string::npos ||
        content.find("string.fromcharcode") != std::string::npos) {
        report.isObfuscated = true;
        report.addFinding("Ofuscacion de script mediante funciones dinamicas (eval/unescape/fromCharCode)", 35);
    }
}

void ScriptAnalyzer::analyzeBatch(const std::string& content, ScriptReport& report) {
    // Detección de ofuscación por inserción masiva de circunflejos (^)
    size_t caretCount = std::count(content.begin(), content.end(), '^');
    if (caretCount > 25 && (caretCount * 10 > content.size())) {
        report.isObfuscated = true;
        report.addFinding("Ofuscacion masiva de lineas de comando mediante carets (^)", 45);
    }

    if (content.find("powershell") != std::string::npos && content.find("-enc") != std::string::npos) {
        report.addFinding("Lote Batch invocando PowerShell con carga util en Base64", 50);
    }
}

HeuristicsEngine::HeuristicsEngine()
    : m_peAnalyzer(std::make_unique<PEAnalyzer>()),
      m_scriptAnalyzer(std::make_unique<ScriptAnalyzer>()) {
}

namespace {

std::string severityFromScore(int score) {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 30) return "medium";
    return "low";
}

std::string joinReasons(const std::vector<std::string>& items) {
    std::string out;
    for (size_t i = 0; i < items.size(); ++i) {
        out += items[i];
        if (i + 1 < items.size()) out += "; ";
    }
    return out;
}

} // namespace

void HeuristicsEngine::addPEThreat(const PEReport& peRep, ScanResult& result) {
    if (!peRep.isValidPE || peRep.heuristicScore <= 0) return;
    result.addThreat(
        peRep.detectedPacker.empty() ? "Heuristic.PE.Suspicious" : ("Packer." + peRep.detectedPacker),
        "heuristic_pe",
        severityFromScore(peRep.heuristicScore),
        peRep.heuristicScore,
        joinReasons(peRep.anomalyReasons)
    );
}

void HeuristicsEngine::addScriptThreat(const ScriptReport& scRep, ScanResult& result) {
    if (scRep.riskScore <= 0) return;
    result.addThreat(
        "Heuristic.Script." + scRep.scriptType,
        "heuristic_script",
        severityFromScore(scRep.riskScore),
        scRep.riskScore,
        joinReasons(scRep.findings)
    );
}

ScanResult HeuristicsEngine::evaluate(const std::filesystem::path& filePath) {
    ScanResult result;
    result.filePath = filePath;

    const std::string ext = paths::extensionLower(filePath);

    // 1. Evaluación de ejecutables y librerías PE
    if (ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".ocx") {
        addPEThreat(m_peAnalyzer->analyze(filePath), result);
    }
    // 2. Evaluación de archivos de scripts
    else if (ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".bat" || ext == ".cmd" || ext == ".hta" || ext == ".wsf") {
        addScriptThreat(m_scriptAnalyzer->analyze(filePath), result);
    }

    return result;
}

} // namespace openguard
