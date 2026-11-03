/**
 * @file heuristics.h
 * @brief Motor unificado de análisis heurístico de scripts y ejecutables para OpenGuard.
 * @details Inspecciona archivos de scripts (PowerShell, VBS, JS, Batch) detectando ofuscación,
 *          cunas de descarga (download cradles), intentos de bypass de AMSI y combina
 *          los resultados con el analizador PE nativo.
 */

#pragma once

#include "openguard/types.h"
#include "openguard/pe_analyzer.h"

#include <string>
#include <vector>
#include <filesystem>
#include <memory>

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

private:
    std::unique_ptr<PEAnalyzer> m_peAnalyzer;
    std::unique_ptr<ScriptAnalyzer> m_scriptAnalyzer;
};

} // namespace openguard

