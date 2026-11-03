/**
 * @file types.h
 * @brief Definiciones de tipos fundamentales, enumeraciones y estructuras de OpenGuard.
 * @details Contiene los modelos de datos para resultados de escaneo, niveles de riesgo,
 *          clasificación de amenazas y estadísticas de rendimiento.
 */

#pragma once

#include <algorithm>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>

namespace openguard {

/**
 * @enum RiskLevel
 * @brief Nivel de severidad asignado a un archivo o proceso tras el análisis.
 */
enum class RiskLevel {
    Clean,      ///< Archivo benigno verificado (Puntuación 0).
    Low,        ///< Anomalías menores o sospecha leve (Puntuación 1 a 30).
    Medium,     ///< Heurística sospechosa o comportamiento dudoso (Puntuación 31 a 60).
    High,       ///< Firma maliciosa o indicadores fuertes de malware (Puntuación 61 a 80).
    Critical    ///< Amenaza confirmada, ransomware activo o exploit grave (Puntuación 81 a 100).
};

/**
 * @enum ScanType
 * @brief Modalidad de análisis seleccionada por el usuario o programada por el sistema.
 */
enum class ScanType {
    Quick,      ///< Escaneo de áreas críticas (Memoria, Temp, AppData, Inicio).
    Full,       ///< Análisis exhaustivo de todas las unidades de almacenamiento fijas.
    Custom,     ///< Análisis de una ruta o archivo específico seleccionado.
    USB,        ///< Escaneo automático de unidades extraíbles conectadas.
    Memory      ///< Inspección de procesos en ejecución y DLLs cargadas en RAM.
};

/**
 * @struct ThreatInfo
 * @brief Representa un hallazgo específico de amenaza detectado por un motor de inspección.
 */
struct ThreatInfo {
    std::string name;       ///< Nombre descriptivo de la amenaza (ej: "Trojan.Generic", "EICAR-Test").
    std::string method;     ///< Método que originó la detección ("hash_signature", "yara", "heuristic").
    std::string severity;   ///< Severidad asignada ("low", "medium", "high", "critical").
    int score{0};           ///< Puntuación de riesgo acumulada para este hallazgo (0 a 100).
    std::string details;    ///< Información adicional o contexto técnico de la detección.
};

/**
 * @struct ScanResult
 * @brief Contiene el informe detallado del análisis realizado sobre un único archivo.
 */
struct ScanResult {
    std::filesystem::path filePath;         ///< Ruta absoluta del archivo analizado.
    RiskLevel riskLevel{RiskLevel::Clean};   ///< Nivel de riesgo consolidado.
    int riskScore{0};                       ///< Puntuación de riesgo numérica (0 a 100).
    std::vector<ThreatInfo> threats;        ///< Colección de amenazas detectadas en el elemento.
    std::string sha256;                     ///< Hash criptográfico SHA-256 en formato hexadecimal.
    std::string sha1;                       ///< Hash criptográfico SHA-1 en formato hexadecimal.
    std::string md5;                        ///< Hash criptográfico MD5 en formato hexadecimal.
    double scanTimeMs{0.0};                 ///< Tiempo consumido en el análisis expresado en milisegundos.
    std::string error;                      ///< Descripción del error en caso de fallo de acceso.
    bool skipped{false};                    ///< Indica si el archivo fue omitido por tamaño o permisos.

    /**
     * @brief Registra un nuevo hallazgo de amenaza y recalcula el nivel de riesgo.
     * @param name Nombre de la amenaza.
     * @param method Método que la detectó.
     * @param severity Severidad en cadena ("low", "medium", "high", "critical").
     * @param score Puntos de riesgo a sumar.
     * @param details Información técnica adicional.
     */
    void addThreat(const std::string& name,
                   const std::string& method,
                   const std::string& severity,
                   int score,
                   const std::string& details = "") {
        threats.push_back({name, method, severity, score, details});
        riskScore = std::min(100, riskScore + score);
        updateRiskLevel();
    }

    /**
     * @brief Determina si el resultado representa una amenaza procesable.
     * @return true si el riesgo es Medium, High o Critical; false en caso contrario.
     */
    [[nodiscard]] bool isThreat() const noexcept {
        return riskLevel != RiskLevel::Clean && riskLevel != RiskLevel::Low;
    }

private:
    /**
     * @brief Actualiza la enumeración RiskLevel en función de la puntuación acumulada.
     */
    void updateRiskLevel() noexcept {
        if (riskScore == 0) {
            riskLevel = RiskLevel::Clean;
        } else if (riskScore <= 30) {
            riskLevel = RiskLevel::Low;
        } else if (riskScore <= 60) {
            riskLevel = RiskLevel::Medium;
        } else if (riskScore <= 80) {
            riskLevel = RiskLevel::High;
        } else {
            riskLevel = RiskLevel::Critical;
        }
    }
};

/**
 * @struct ScanSessionStats
 * @brief Resumen cuantitativo consolidado de una sesión de escaneo completa.
 */
struct ScanSessionStats {
    ScanType scanType{ScanType::Custom};                ///< Tipo de sesión ejecutada.
    size_t filesScanned{0};                             ///< Total de archivos procesados exitosamente.
    size_t filesSkipped{0};                             ///< Total de archivos omitidos por restricciones.
    size_t threatsFound{0};                             ///< Número total de elementos con amenazas.
    std::chrono::milliseconds duration{0};              ///< Duración total de la sesión.
    std::vector<ScanResult> results;                    ///< Resultados individuales detallados.
};

} // namespace openguard

