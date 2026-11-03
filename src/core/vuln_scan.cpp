/**
 * @file vuln_scan.cpp
 * @brief Implementación de las comprobaciones de vulnerabilidad y configuraciones de Windows.
 * @details Consulta el Registro de Windows y la API de gestión de red para auditar mitigaciones,
 *          firewall, UAC, SMBv1 y servicios expuestos.
 */

#include "openguard/vuln_scan.h"

#include <windows.h>
#include <lm.h>

#pragma comment(lib, "netapi32.lib")

namespace openguard {

namespace {

/**
 * @brief Lee un valor DWORD del Registro de Windows de forma segura.
 * @param hKey Hive raíz (ej: HKEY_LOCAL_MACHINE).
 * @param subKey Ruta de la subclave.
 * @param valueName Nombre del valor a consultar.
 * @param[out] outValue Variable donde se deposita el valor obtenido.
 * @return true si el valor existe y se leyó correctamente; false en caso contrario.
 */
bool readRegistryDword(HKEY hKey, LPCWSTR subKey, LPCWSTR valueName, DWORD& outValue) {
    HKEY keyHandle = nullptr;
    LSTATUS status = RegOpenKeyExW(hKey, subKey, 0, KEY_READ, &keyHandle);
    if (status != ERROR_SUCCESS) return false;

    DWORD dataSize = sizeof(DWORD);
    DWORD type = 0;
    status = RegQueryValueExW(keyHandle, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&outValue), &dataSize);
    RegCloseKey(keyHandle);

    return (status == ERROR_SUCCESS) && (type == REG_DWORD);
}

} // namespace anónimo

VulnReport VulnerabilityScanner::scanSystemSecurity() {
    VulnReport report;

    checkUacStatus(report);
    checkDefenderStatus(report);
    checkFirewallStatus(report);
    checkSmbv1Status(report);
    checkRdpExposure(report);
    checkGuestAccount(report);

    return report;
}

void VulnerabilityScanner::checkUacStatus(VulnReport& report) {
    DWORD enableLua = 1;
    if (readRegistryDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", enableLua)) {
        if (enableLua == 0) {
            VulnFinding f;
            f.category = "uac";
            f.description = "User Account Control (UAC) se encuentra completamente DESHABILITADO";
            f.severity = "high";
            f.score = 50;
            f.remediation = "Habilitar UAC: Establecer EnableLUA en 1 en HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
            report.addFinding(f);
        }
    }
}

void VulnerabilityScanner::checkDefenderStatus(VulnReport& report) {
    DWORD disableAntiSpyware = 0;
    if (readRegistryDword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"DisableAntiSpyware", disableAntiSpyware)) {
        if (disableAntiSpyware == 1) {
            VulnFinding f;
            f.category = "defender";
            f.description = "Windows Defender (Antivirus nativo) ha sido DESHABILITADO mediante politicas";
            f.severity = "critical";
            f.score = 75;
            f.remediation = "Eliminar o poner en 0 el valor DisableAntiSpyware en HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender";
            report.addFinding(f);
        }
    }
}

void VulnerabilityScanner::checkFirewallStatus(VulnReport& report) {
    // Comprobar los 3 perfiles del Firewall de Windows: Dominio, Estándar y Público
    const LPCWSTR profiles[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    };

    const char* profileNames[] = {"Dominio", "Estandar (Privado)", "Publico"};

    for (size_t i = 0; i < 3; ++i) {
        DWORD enableFw = 1;
        if (readRegistryDword(HKEY_LOCAL_MACHINE, profiles[i], L"EnableFirewall", enableFw)) {
            if (enableFw == 0) {
                VulnFinding f;
                f.category = "firewall";
                f.description = std::string("Windows Firewall esta DESACTIVADO en el perfil: ") + profileNames[i];
                f.severity = "high";
                f.score = 45;
                f.remediation = "Activar el firewall en Seguridad de Windows o comando: netsh advfirewall set allprofiles state on";
                report.addFinding(f);
            }
        }
    }
}

void VulnerabilityScanner::checkSmbv1Status(VulnReport& report) {
    // En Windows, SMBv1 en LanmanServerParameters con valor SMB1 = 1 indica protocolo activo
    DWORD smb1Val = 0;
    if (readRegistryDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"SMB1", smb1Val)) {
        if (smb1Val == 1) {
            VulnFinding f;
            f.category = "smbv1";
            f.description = "Protocolo SMBv1 activo en el servidor local (Vector de explotacion EternalBlue / WannaCry)";
            f.severity = "critical";
            f.score = 70;
            f.cve = "CVE-2017-0144";
            f.remediation = "Deshabilitar SMBv1 ejecutando en PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol";
            report.addFinding(f);
        }
    }
}

void VulnerabilityScanner::checkRdpExposure(VulnReport& report) {
    DWORD denyTs = 1;
    if (readRegistryDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", L"fDenyTSConnections", denyTs)) {
        if (denyTs == 0) {
            VulnFinding f;
            f.category = "rdp";
            f.description = "Escritorio Remoto (RDP) esta habilitado en el equipo y podria estar expuesto a la red";
            f.severity = "medium";
            f.score = 30;
            f.remediation = "Si no utiliza Escritorio Remoto, deshabilitelo en Configuracion > Sistema > Escritorio Remoto";
            report.addFinding(f);
        }
    }
}

void VulnerabilityScanner::checkGuestAccount(VulnReport& report) {
    USER_INFO_1* userInfo = nullptr;
    NET_API_STATUS nStatus = NetUserGetInfo(nullptr, L"Guest", 1, reinterpret_cast<LPBYTE*>(&userInfo));

    if (nStatus == NERR_Success && userInfo) {
        // UF_ACCOUNTDISABLE = 0x0002
        if ((userInfo->usri1_flags & UF_ACCOUNTDISABLE) == 0) {
            VulnFinding f;
            f.category = "accounts";
            f.description = "La cuenta de usuario 'Guest' (Invitado) se encuentra HABILITADA en el sistema";
            f.severity = "medium";
            f.score = 30;
            f.remediation = "Deshabilitar la cuenta de invitado: net user Guest /active:no";
            report.addFinding(f);
        }
        NetApiBufferFree(userInfo);
    }
}

} // namespace openguard

