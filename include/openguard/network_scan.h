/**
 * @file network_scan.h
 * @brief Auditor de red, conexiones activas y persistencia de red para OpenGuard.
 * @details Utiliza la API IP Helper de Windows (iphlpapi) para enumerar la tabla TCP/UDP
 *          con PIDs propietarios, detecta conexiones hacia puertos C2/RAT y analiza secuestros
 *          del archivo hosts, DNS y configuración de proxy.
 */

#pragma once

#include "openguard/types.h"

#include <string>
#include <vector>
#include <cstdint>

namespace openguard {

/**
 * @struct NetworkConnection
 * @brief Información detallada de un socket de red activo en el sistema.
 */
struct NetworkConnection {
    std::string protocol;       ///< "TCP" o "UDP".
    std::string localAddress;   ///< Dirección IP y puerto local (ej: "192.168.1.50:49200").
    std::string remoteAddress;  ///< Dirección IP y puerto remoto (ej: "185.220.101.5:4444").
    std::string state;          ///< Estado de la conexión ("ESTABLISHED", "LISTENING", etc.).
    uint32_t pid{0};            ///< Identificador del proceso propietario del socket.
    std::string processName;    ///< Nombre del binario ejecutable que abrió la conexión.
    bool isSuspicious{false};   ///< true si el puerto remoto o local pertenece a una lista de C2 conocidos.
    std::string alertReason;    ///< Motivo de sospecha si aplica.
};

/**
 * @struct NetworkFinding
 * @brief Anomalía de seguridad o secuestro de configuración de red detectado.
 */
struct NetworkFinding {
    std::string category;       ///< "suspicious_port", "hosts_hijack", "proxy_hijack", "listener".
    std::string description;    ///< Detalle técnico del riesgo.
    std::string severity;       ///< "medium", "high", "critical".
    int score{0};               ///< Puntos de riesgo (0 a 100).
    std::string detail;         ///< Evidencia técnica encontrada.
};

/**
 * @struct NetworkScanReport
 * @brief Informe consolidado de la auditoría de red del equipo.
 */
struct NetworkScanReport {
    std::vector<NetworkConnection> activeConnections;   ///< Tabla completa de sockets analizados.
    std::vector<NetworkFinding> findings;               ///< Anomalías detectadas.
    int totalRiskScore{0};                              ///< Puntuación de riesgo acumulada.

    void addFinding(const NetworkFinding& f) {
        findings.push_back(f);
        totalRiskScore = std::min(100, totalRiskScore + f.score);
    }
};

/**
 * @class NetworkScanner
 * @brief Analizador de sockets de red y vectores de comunicación maliciosos en Windows.
 */
class NetworkScanner {
public:
    NetworkScanner() = default;
    ~NetworkScanner() = default;

    /**
     * @brief Ejecuta el escaneo completo de red: sockets TCP/UDP, hosts, proxy y listeners.
     * @return NetworkScanReport con los resultados estructurados.
     */
    [[nodiscard]] NetworkScanReport scanNetwork();

private:
    void enumerateTcpConnections(NetworkScanReport& report);
    void checkHostsFile(NetworkScanReport& report);
    void checkProxySettings(NetworkScanReport& report);
    static std::string getProcessNameFromPid(uint32_t pid);
};

} // namespace openguard

