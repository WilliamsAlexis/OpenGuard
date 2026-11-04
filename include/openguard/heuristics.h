/**
 * @file heuristics.h
 * @brief Motor unificado de análisis heurístico de scripts y ejecutables para OpenGuard.
 * @details Inspecciona archivos de scripts (PowerShell, VBS, JS, Batch) detectando ofuscación,
 *          cunas de descarga (download cradles), intentos de bypass de AMSI y combina
 *          los resultados con el analizador PE nativo.
 */

#pragma once

#include "openguard/types.h"
#include "openguard/office_macros.h"
#include "openguard/pe_analyzer.h"

#include <string>
#include <vector>
#include <filesystem>
#include <memory>
#include <optional>

namespace openguard {

/**
 * @struct ScriptReport
 * @brief Resultado del análisis estático de un archivo de script.
 */
struct ScriptReport {
    std::filesystem::path filePath;         ///< Ruta del archivo de script analizado.
    std::string scriptType;                 ///< Tipo de lenguaje ("PowerShell", "VBScript", "JScript", "Batch").
    bool isObfuscated{false};               ///< true si se identificó ofuscación deliberada.
    double entropy{0.0};                    ///< Entropía de caracteres del script.
    int riskScore{0};                       ///< Puntuación de riesgo acumulada (0 a 100).
    std::vector<std::string> findings;      ///< Lista descriptiva de los patrones sospechosos encontrados.

    /**
     * @brief Añade un hallazgo y suma puntos al riesgo del script.
     * @param description Detalle del patrón o técnica identificada.
     * @param score Puntos a sumar.
     */
    void addFinding(const std::string& description, int score) {
        findings.push_back(description);
        riskScore = std::min(100, riskScore + score);
    }
};

/**
 * @class ScriptAnalyzer
 * @brief Motor especializado en inspección sintáctica y de patrones de scripts para Windows.
 */
class ScriptAnalyzer {
public:
    ScriptAnalyzer() = default;
    ~ScriptAnalyzer() = default;

    /**
     * @brief Analiza el contenido de un archivo de script buscando técnicas maliciosas.
     * @param filePath Ruta del script a examinar.
     * @return ScriptReport con los hallazgos y evaluación de riesgo.
     */
    [[nodiscard]] ScriptReport analyze(const std::filesystem::path& filePath);

    /// Analiza el contenido de un script ya cargado en memoria (extension tomada de filePath).
    [[nodiscard]] ScriptReport analyzeContent(std::string content, const std::filesystem::path& filePath);

private:
    void analyzePowerShell(const std::string& content, ScriptReport& report);
    void analyzeVbsJs(const std::string& content, ScriptReport& report);
    void analyzeBatch(const std::string& content, ScriptReport& report);
};

/**
 * @class HeuristicsEngine
 * @brief Orquestador heurístico central que selecciona el analizador adecuado según el tipo de archivo.
 */
class HeuristicsEngine {
public:
    HeuristicsEngine();
    ~HeuristicsEngine() = default;

    /**
     * @brief Ejecuta el análisis heurístico sobre cualquier archivo (PE o script).
     * @param filePath Ruta del archivo a examinar.
     * @return ScanResult con las amenazas heurísticas detectadas.
     */
    [[nodiscard]] ScanResult evaluate(const std::filesystem::path& filePath);

    /// Convierte un informe PE en una amenaza heurística (si su puntuación es > 0).
    static void addPEThreat(const PEReport& report, ScanResult& result);

    /// Convierte un informe de script en una amenaza heurística (si su puntuación es > 0).
    static void addScriptThreat(const ScriptReport& report, ScanResult& result);

    /// Convierte un informe de macros de Office en una amenaza heurística (solo si hay macros).
    static void addOfficeThreat(const MacroReport& report, ScanResult& result);

    /**
     * @brief Indicio débil por la ubicación: ejecutables/scripts en carpetas temporales, AppData\Roaming, Papelera,
     *        Public o Descargas. Por sí solo nunca llega al umbral de amenaza; suma a otros indicios.
     */
    [[nodiscard]] static std::optional<ThreatInfo> suspiciousLocation(const std::filesystem::path& file);

    /**
     * @brief Ajusta la confianza de una coincidencia de contenido (YARA o heurística de script) según el archivo.
     * @details Las reglas buscan cadenas típicas de malware (APIs de teclado, "exec", sockets...) que aparecen en el
     *          código fuente de cualquier librería. Por eso:
     *          - dentro de carpetas de librerías/desarrollo (node_modules, site-packages, .git...) lo no crítico se descarta;
     *          - una coincidencia YARA no crítica en archivos de texto/código (.js, .json, .md...) solo pesa un poco
     *            (la primera 10 puntos, el resto 0), insuficiente por sí sola para considerarlo amenaza.
     *          Las coincidencias críticas y las firmas por hash nunca se alteran.
     * @param weakSeen Contador por archivo de coincidencias débiles ya aplicadas (empezar en 0).
     * @return Puntuación a usar, o -1 si debe descartarse.
     */
    [[nodiscard]] static int weighContentMatch(const std::filesystem::path& file, const std::string& method,
                                               const std::string& severity, int score, int& weakSeen);

private:
    std::unique_ptr<PEAnalyzer> m_peAnalyzer;
    std::unique_ptr<ScriptAnalyzer> m_scriptAnalyzer;
};

} // namespace openguard

