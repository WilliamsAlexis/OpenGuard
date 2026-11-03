/**
 * @file vuln_scan.h
 * @brief Auditor de vulnerabilidades del sistema y configuraciones críticas de Windows.
 * @details Inspecciona el estado de seguridad de Windows: UAC, Defender, Firewall,
 *          exposición de RDP, activación del protocolo vulnerable SMBv1 (EternalBlue)
 *          y cuentas locales con privilegios riesgosos.
 */

#pragma once

#include "openguard/types.h"

#include <string>
#include <vector>

namespace openguard {

/**
 * @struct VulnFinding
 * @brief Describe una vulnerabilidad, desconfiguración o debilidad encontrada en el equipo.
 */
struct VulnFinding {
    std::string category;       ///< Categoría ("uac", "firewall", "defender", "smbv1", "rdp").
    std::string description;    ///< Resumen explicativo del riesgo detectado.
    std::string severity;       ///< Nivel de riesgo ("low", "medium", "high", "critical").
    int score{0};               ///< Puntos de penalización de seguridad (0 a 100).
    std::string remediation;    ///< Pasos exactos o comando recomendado para subsanar la debilidad.
    std::string cve;            ///< Identificador CVE asociado si aplica (ej: "CVE-2017-0144").
};

/**
 * @struct VulnReport
 * @brief Informe cuantitativo y cualitativo de la salud de seguridad del sistema operativo.
 */
struct VulnReport {
    std::vector<VulnFinding> findings;  ///< Desglose de vulnerabilidades detectadas.
    int totalRiskScore{0};              ///< Puntuación de riesgo acumulada (0 a 100).
    int systemHealthScore{100};         ///< Puntuación de salud general (100 = óptimo, 0 = crítico).

    /**
     * @brief Añade una vulnerabilidad al reporte y recalcula la puntuación de salud.
     * @param finding Vulnerabilidad a registrar.
     */
    void addFinding(const VulnFinding& finding) {
        findings.push_back(finding);
        totalRiskScore = std::min(100, totalRiskScore + finding.score);
        systemHealthScore = std::max(0, systemHealthScore - (finding.score / 2));
    }
};

/**
 * @class VulnerabilityScanner
 * @brief Motor auditor de configuraciones de seguridad y mitigaciones en Windows 10/11.
 */
class VulnerabilityScanner {
public:
    VulnerabilityScanner() = default;
    ~VulnerabilityScanner() = default;

    /**
     * @brief Ejecuta la auditoría integral de seguridad y configuraciones del equipo.
     * @return VulnReport con los hallazgos y recomendaciones de mitigación.
     */
    [[nodiscard]] VulnReport scanSystemSecurity();

private:
    void checkUacStatus(VulnReport& report);
    void checkDefenderStatus(VulnReport& report);
    void checkFirewallStatus(VulnReport& report);
    void checkSmbv1Status(VulnReport& report);
    void checkRdpExposure(VulnReport& report);
    void checkGuestAccount(VulnReport& report);
};

} // namespace openguard

