/**
 * @file content_analysis.h
 * @brief Análisis estático del CONTENIDO de un archivo en memoria, sin acceso a disco ni al sistema.
 * @details Es la parte del motor que procesa datos no confiables (hashes, YARA, estructura PE, scripts).
 *          Se ejecuta en el proceso trabajador aislado (openguard_worker). Lo que necesita servicios del
 *          sistema —consulta de firmas, verificación Authenticode— lo completa el proceso que lo invoca.
 */

#pragma once

#include "openguard/types.h"
#include "openguard/yara_lite.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace openguard {

/// Resultado serializable del análisis de contenido.
struct ContentAnalysis {
    bool ok{false};
    std::string error;
    std::string sha256, sha1, md5;
    std::vector<ThreatInfo> threats;      ///< Detecciones de YARA y de heurística de scripts (ya puntuadas).

    // PE: se devuelve el informe SIN el ajuste por firma digital, que lo aplica quien tenga acceso al sistema.
    bool isPE{false};
    int peScore{0};
    std::vector<std::string> peReasons;
    std::string peDetectedPacker;
};

/**
 * @brief Analiza un archivo ya cargado en memoria.
 * @param data Contenido completo.
 * @param displayPath Ruta solo para decidir el tipo por extensión y mostrar; NO se abre.
 * @param yara Motor YARA ya cargado (puede ser nulo).
 */
[[nodiscard]] ContentAnalysis analyzeContent(const std::vector<uint8_t>& data,
                                             const std::filesystem::path& displayPath,
                                             const YaraLite* yara);

/// Serialización JSON (UTF-8) usada entre el trabajador y el servicio.
[[nodiscard]] std::string contentAnalysisToJson(const ContentAnalysis& analysis);
[[nodiscard]] bool contentAnalysisFromJson(const std::string& json, ContentAnalysis& out);

} // namespace openguard
