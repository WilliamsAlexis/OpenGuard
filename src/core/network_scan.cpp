/**
 * @file network_scan.cpp
 * @brief Implementación de la auditoría de red mediante IP Helper API y sockets de Windows.
 * @details Inspecciona la tabla TCP extendida con PIDs, detecta puertos RAT comunes (4444, 1337, etc.),
 *          audita el archivo hosts en busca de secuestros y analiza proxys maliciosos.
 */

#include "openguard/network_scan.h"
#include "openguard/paths.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>

#include <fstream>
#include <sstream>
#include <unordered_set>
#include <algorithm>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace openguard {

namespace {

/**
 * @brief Puertos C2 (Command and Control) y RATs frecuentemente abusados por atacantes.
 */
static const std::unordered_set<uint16_t> kKnownC2Ports = {
    4444, 4445, 1337, 31337, 6666, 6667, 9999, 8888, 5555, 1234, 12345
};

/**
 * @brief Convierte un estado de conexión TCP numérico a una cadena descriptiva.
 * @param state Estado numérico devuelto por MIB_TCPROW_OWNER_PID.
 * @return Cadena representativa ("ESTABLISHED", "LISTENING", etc.).
 */
std::string tcpStateToString(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTENING";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "UNKNOWN";
    }
}

/**
 * @brief Convierte una dirección IP binaria en formato red a notación de puntos (IPv4).
 * @param ip Dirección en formato DWORD.
 * @return Cadena con la IP (ej: "192.168.1.1").
 */
std::string ipToString(DWORD ip) {
    in_addr addr{};
    addr.s_addr = ip;
    char strBuf[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &addr, strBuf, sizeof(strBuf))) {
        return strBuf;
    }
    return "0.0.0.0";
}

} // namespace anónimo

std::string NetworkScanner::getProcessNameFromPid(uint32_t pid) {
    if (pid == 0) return "System Idle Process";
    if (pid == 4) return "System";

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "";

    wchar_t exePath[MAX_PATH]{};
    DWORD pathLen = MAX_PATH;
    std::string procName;

    if (QueryFullProcessImageNameW(hProcess, 0, exePath, &pathLen) && pathLen > 0) {
        std::filesystem::path p(exePath);
        procName = paths::toUtf8(p.filename());
    }
    CloseHandle(hProcess);

    return procName;
}

NetworkScanReport NetworkScanner::scanNetwork() {
    NetworkScanReport report;

    enumerateTcpConnections(report);
    checkHostsFile(report);
    checkProxySettings(report);

    return report;
}

void NetworkScanner::enumerateTcpConnections(NetworkScanReport& report) {
    DWORD tableSize = 0;
    // Primera llamada para determinar el tamaño del búfer requerido
    GetExtendedTcpTable(nullptr, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tableSize == 0) return;

    std::vector<uint8_t> buffer(tableSize);
    auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

    if (GetExtendedTcpTable(tcpTable, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
            const auto& row = tcpTable->table[i];

            NetworkConnection conn;
            conn.protocol = "TCP";
            conn.state = tcpStateToString(row.dwState);
            conn.pid = row.dwOwningPid;
            conn.processName = getProcessNameFromPid(conn.pid);

            uint16_t localPort = ntohs(static_cast<uint16_t>(row.dwLocalPort));
            uint16_t remotePort = ntohs(static_cast<uint16_t>(row.dwRemotePort));

            std::string localIp = ipToString(row.dwLocalAddr);
            std::string remoteIp = ipToString(row.dwRemoteAddr);

            conn.localAddress = localIp + ":" + std::to_string(localPort);
            conn.remoteAddress = remoteIp + ":" + std::to_string(remotePort);

            // Detección de conexiones salientes sospechosas hacia puertos C2
            if (row.dwState == MIB_TCP_STATE_ESTAB && remoteIp != "127.0.0.1" && remoteIp != "0.0.0.0") {
                if (kKnownC2Ports.find(remotePort) != kKnownC2Ports.end()) {
                    conn.isSuspicious = true;
                    conn.alertReason = "Conexion activa hacia puerto de control C2/RAT sospechoso: " + std::to_string(remotePort);

                    NetworkFinding f;
                    f.category = "suspicious_port";
                    f.description = "Proceso '" + conn.processName + "' (PID " + std::to_string(conn.pid) +
                                    ") conectado a puerto C2 sospechoso: " + std::to_string(remotePort);
                    f.severity = "high";
                    f.score = 60;
                    f.detail = conn.localAddress + " -> " + conn.remoteAddress;
                    report.addFinding(f);
                }
            }

            // Detección de listeners abiertos en puertos de riesgo
            if (row.dwState == MIB_TCP_STATE_LISTEN) {
                if (kKnownC2Ports.find(localPort) != kKnownC2Ports.end()) {
                    conn.isSuspicious = true;
                    conn.alertReason = "Puerto sospechoso escuchando localmente: " + std::to_string(localPort);

                    NetworkFinding f;
                    f.category = "listener";
                    f.description = "Proceso '" + conn.processName + "' (PID " + std::to_string(conn.pid) +
                                    ") escuchando en puerto sospechoso: " + std::to_string(localPort);
                    f.severity = "high";
                    f.score = 55;
                    f.detail = "Escuchando en " + conn.localAddress;
                    report.addFinding(f);
                }
            }

            report.activeConnections.push_back(conn);
        }
    }
}

void NetworkScanner::checkHostsFile(NetworkScanReport& report) {
    std::filesystem::path hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    std::ifstream file(hostsPath);
    if (!file.is_open()) return;

    std::string line;
    std::vector<std::string> hijackedEntries;

    while (std::getline(file, line)) {
        // Ignorar líneas vacías o comentarios
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string ip, domain;
        if (iss >> ip >> domain) {
            std::string dLower = domain;
            std::transform(dLower.begin(), dLower.end(), dLower.begin(), ::tolower);

            // Comprobar redirecciones de servicios críticos de seguridad o actualización
            if (dLower.find("windowsupdate") != std::string::npos ||
                dLower.find("microsoft.com") != std::string::npos ||
                dLower.find("kaspersky") != std::string::npos ||
                dLower.find("malwarebytes") != std::string::npos) {
                if (ip != "127.0.0.1" && ip != "0.0.0.0" && ip != "::1") {
                    hijackedEntries.push_back(ip + " " + domain);
                }
            }
        }
    }

    if (!hijackedEntries.empty()) {
        NetworkFinding f;
        f.category = "hosts_hijack";
        f.description = "Archivo hosts de Windows alterado para desviar dominios de seguridad o actualizaciones";
        f.severity = "critical";
        f.score = 85;
        for (const auto& entry : hijackedEntries) {
            f.detail += entry + "; ";
        }
        report.addFinding(f);
    }
}

void NetworkScanner::checkProxySettings(NetworkScanReport& report) {
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        0,
        KEY_READ,
        &hKey
    );

    if (status != ERROR_SUCCESS) return;

    DWORD proxyEnable = 0;
    DWORD dataSize = sizeof(DWORD);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, L"ProxyEnable", nullptr, &type, reinterpret_cast<LPBYTE>(&proxyEnable), &dataSize) == ERROR_SUCCESS) {
        if (proxyEnable == 1) {
            wchar_t proxyServer[256]{};
            DWORD strSize = sizeof(proxyServer);
            if (RegQueryValueExW(hKey, L"ProxyServer", nullptr, &type, reinterpret_cast<LPBYTE>(proxyServer), &strSize) == ERROR_SUCCESS) {
                std::wstring wProxy(proxyServer);
                // Si el proxy apunta a localhost en puertos inusuales, puede ser un troyano interceptor (MITM local)
                if (wProxy.find(L"127.0.0.1") != std::wstring::npos || wProxy.find(L"localhost") != std::wstring::npos) {
                    NetworkFinding f;
                    f.category = "proxy_hijack";
                    f.description = "Proxy local configurado en Windows (posible malware realizando MITM local)";
                    f.severity = "high";
                    f.score = 60;
                    int len = WideCharToMultiByte(CP_UTF8, 0, wProxy.c_str(), -1, nullptr, 0, nullptr, nullptr); if (len > 1) { f.detail.resize(len - 1); WideCharToMultiByte(CP_UTF8, 0, wProxy.c_str(), -1, f.detail.data(), len, nullptr, nullptr); }
                    report.addFinding(f);
                }
            }
        }
    }

    RegCloseKey(hKey);
}

} // namespace openguard
