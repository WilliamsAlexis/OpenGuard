/**
 * @file main_cli.cpp
 * @brief Punto de entrada de la interfaz de consola (CLI) de OpenGuard.
 * @details Permite ejecutar análisis rápidos, completos, personalizados, auditorías de red,
 *          vulnerabilidades del sistema, análisis PE y gestión de cuarentena cifrada.
 */

#include "openguard/scanner.h"
#include "openguard/signatures.h"
#include "openguard/pe_analyzer.h"
#include "openguard/quarantine.h"
#include "openguard/vuln_scan.h"
#include "openguard/network_scan.h"

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

namespace {

/**
 * @brief Imprime el logotipo y banner de inicio en la terminal.
 */
void printBanner() {
    std::cout << "\n"
              << "=========================================================\n"
              << "       OpenGuard Antivirus para Windows (C++20)          \n"
              << "   Seguridad Defensiva | Gratuito y de Codigo Abierto   \n"
              << "=========================================================\n\n";
}

/**
 * @brief Muestra las instrucciones de uso y comandos disponibles en la consola.
 * @param progName Nombre del ejecutable invocado.
 */
void printHelp(const char* progName) {
    std::cout << "Uso: " << progName << " <comando> [opciones]\n\n"
              << "Comandos de Escaneo de Archivos:\n"
              << "  scan <ruta>             Analiza un archivo o directorio especifico.\n"
              << "  quick                   Ejecuta un analisis rapido de areas criticas.\n"
              << "  full                    Inicia un escaneo exhaustivo de todas las unidades.\n"
              << "  pe <ruta_ejecutable>    Analisis estatico profundo de estructura PE y firma digital.\n\n"
              << "Comandos de Auditoria del Sistema:\n"
              << "  vuln                    Audita configuraciones de seguridad de Windows (UAC, SMBv1, Firewall).\n"
              << "  network                 Audita conexiones TCP/UDP activas, puertos C2 y archivo hosts.\n\n"
              << "Comandos de Cuarentena Cifrada:\n"
              << "  quarantine list         Lista todos los elementos aislados en la boveda.\n"
              << "  quarantine restore <id> Restaura un elemento a su ubicacion original.\n"
              << "  quarantine delete <id>  Destruye permanentemente un elemento con sobreescritura segura.\n\n"
              << "Otros Comandos:\n"
              << "  stats                   Muestra metricas de la base de datos de firmas.\n"
              << "  --help, -h              Muestra esta ayuda en pantalla.\n"
              << "  --version, -v           Informa la version de OpenGuard instalada.\n\n";
}

/**
 * @brief Presenta un resumen final formateado de la sesion de analisis completada.
 * @param session Estructura con las metricas consolidadas.
 */
void printSessionSummary(const openguard::ScanSessionStats& session) {
    std::cout << "\n---------------------------------------------------------\n"
              << "             Resumen del Analisis de OpenGuard           \n"
              << "---------------------------------------------------------\n"
              << " Archivos analizados  : " << session.filesScanned << "\n"
              << " Archivos omitidos    : " << session.filesSkipped << "\n"
              << " Amenazas detectadas  : " << session.threatsFound << "\n"
              << " Tiempo transcurrido  : " << session.duration.count() << " ms ("
              << std::fixed << std::setprecision(2) << (session.duration.count() / 1000.0) << " s)\n"
              << "---------------------------------------------------------\n";

    if (session.threatsFound > 0) {
        std::cout << "\n[!] ALERTA: SE DETECTARON ELEMENTOS MALICIOSOS:\n";
        for (const auto& res : session.results) {
            if (res.isThreat()) {
                std::cout << "\n  [!] Elemento: " << res.filePath.string() << "\n"
                          << "      Nivel de Riesgo : " << static_cast<int>(res.riskLevel)
                          << " (Puntos: " << res.riskScore << "/100)\n"
                          << "      SHA-256         : " << res.sha256 << "\n";
                for (const auto& threat : res.threats) {
                    std::cout << "      - Amenaza : [" << threat.severity << "] "
                              << threat.name << " (" << threat.method << ")\n";
                    if (!threat.details.empty()) {
                        std::cout << "        Detalle : " << threat.details << "\n";
                    }
                }
            }
        }
        std::cout << "\n";
    } else {
        std::cout << "\n[+] El analisis no encontro amenazas conocidas ni anomalias.\n\n";
    }
}

} // namespace anónimo

int main(int argc, char* argv[]) {
    printBanner();

    if (argc < 2) {
        printHelp(argv[0]);
        return 0;
    }

    std::string command = argv[1];

    if (command == "--help" || command == "-h") {
        printHelp(argv[0]);
        return 0;
    }

    if (command == "--version" || command == "-v") {
        std::cout << "OpenGuard version 0.1.0 (Edicion Nativa Windows C++20)\n";
        return 0;
    }

    // Inicializar base de datos de firmas SQLite
    std::filesystem::path dbPath = "signatures/hashes.db";
    auto sigDb = std::make_shared<openguard::SignatureDB>(dbPath);
    sigDb->seedEicar();

    // 1. Estadísticas de firmas
    if (command == "stats") {
        auto stats = sigDb->getStats();
        std::cout << "Estado de la Base de Firmas (" << dbPath.string() << "):\n"
                  << "  Total de firmas cargadas: " << stats.totalSignatures << "\n";
        for (const auto& [sev, count] : stats.bySeverity) {
            std::cout << "    - " << sev << ": " << count << "\n";
        }
        return 0;
    }

    // 2. Auditoría de Vulnerabilidades y Configuraciones del Sistema
    if (command == "vuln") {
        std::cout << "[*] Iniciando auditoria de seguridad del sistema operativo...\n";
        openguard::VulnerabilityScanner vulnScanner;
        auto report = vulnScanner.scanSystemSecurity();

        std::cout << "\n---------------------------------------------------------\n"
                  << "      Resultados de Seguridad y Mitigaciones Windows     \n"
                  << "---------------------------------------------------------\n"
                  << " Puntuacion de Salud de Seguridad : " << report.systemHealthScore << " / 100\n"
                  << " Puntuacion de Riesgo Acumulado   : " << report.totalRiskScore << " / 100\n"
                  << " Hallazgos detectados             : " << report.findings.size() << "\n"
                  << "---------------------------------------------------------\n";

        if (report.findings.empty()) {
            std::cout << "[+] El sistema cumple con las directivas de seguridad recomendadas.\n\n";
        } else {
            for (const auto& f : report.findings) {
                std::cout << "\n  [" << f.severity << "] " << f.description << "\n"
                          << "     Solucion: " << f.remediation << "\n";
                if (!f.cve.empty()) {
                    std::cout << "     CVE     : " << f.cve << "\n";
                }
            }
            std::cout << "\n";
        }
        return report.totalRiskScore > 50 ? 1 : 0;
    }

    // 3. Auditoría de Red y Conexiones Activas
    if (command == "network") {
        std::cout << "[*] Inspeccionando sockets de red, tabla TCP y puertos de comunicacion...\n";
        openguard::NetworkScanner netScanner;
        auto report = netScanner.scanNetwork();

        std::cout << "\n---------------------------------------------------------\n"
                  << "              Auditoria de Conexiones de Red             \n"
                  << "---------------------------------------------------------\n"
                  << " Sockets TCP inspeccionados : " << report.activeConnections.size() << "\n"
                  << " Hallazgos o alertas de red : " << report.findings.size() << "\n"
                  << "---------------------------------------------------------\n";

        if (!report.findings.empty()) {
            std::cout << "[!] CONEXIONES O CONFIGURACIONES SOSPECHOSAS DETECTADAS:\n";
            for (const auto& f : report.findings) {
                std::cout << "  [" << f.severity << "] " << f.description << "\n"
                          << "      Detalle: " << f.detail << "\n";
            }
            std::cout << "\n";
        } else {
            std::cout << "[+] No se encontraron conexiones a puertos C2 ni secuestros de red.\n\n";
        }
        return 0;
    }

    // 4. Gestión de Cuarentena Cifrada AES-256
    if (command == "quarantine") {
        openguard::QuarantineVault vault;

        if (argc >= 3) {
            std::string sub = argv[2];
            if (sub == "list") {
                auto items = vault.listItems();
                std::cout << "Boveda de Cuarentena (" << items.size() << " elementos resguardados):\n";
                for (const auto& item : items) {
                    std::cout << "  [" << item.qid << "] " << item.threatName << " (" << item.severity << ")\n"
                              << "      Ruta Original : " << item.originalPath.string() << "\n"
                              << "      Fecha         : " << item.quarantinedAt << "\n"
                              << "      SHA-256       : " << item.sha256 << "\n\n";
                }
                return 0;
            }
            if (sub == "restore" && argc >= 4) {
                std::string qid = argv[3];
                bool ok = vault.restoreFile(qid);
                std::cout << (ok ? "[+] Archivo restaurado exitosamente a su ruta original.\n"
                                 : "[!] Fallo al restaurar el archivo de la cuarentena.\n");
                return ok ? 0 : 1;
            }
            if (sub == "delete" && argc >= 4) {
                std::string qid = argv[3];
                bool ok = vault.deletePermanently(qid);
                std::cout << (ok ? "[+] Archivo purgado de la boveda con sobreescritura segura.\n"
                                 : "[!] Fallo al eliminar el elemento de la cuarentena.\n");
                return ok ? 0 : 1;
            }
        }

        std::cout << "Uso de cuarentena:\n"
                  << "  quarantine list\n"
                  << "  quarantine restore <qid>\n"
                  << "  quarantine delete <qid>\n";
        return 0;
    }

    // 5. Análisis Estático Profundo de PE
    if (command == "pe") {
        if (argc < 3) {
            std::cerr << "[!] Error: Debe indicar la ruta del ejecutable PE.\n";
            return 1;
        }
        std::filesystem::path target = argv[2];
        std::cout << "[*] Analizando estructura binaria PE de: " << target.string() << "\n";

        openguard::PEAnalyzer peAnalyzer;
        auto rep = peAnalyzer.analyze(target);

        if (!rep.isValidPE) {
            std::cout << "[!] El archivo no es un ejecutable PE de Windows valido.\n";
            return 1;
        }

        std::cout << "\n---------------------------------------------------------\n"
                  << "              Reporte de Analisis Estatico PE            \n"
                  << "---------------------------------------------------------\n"
                  << " Arquitectura        : " << (rep.is64Bit ? "64-bit (PE32+)" : "32-bit (PE32)") << "\n"
                  << " Tipo de Binario     : " << (rep.isDLL ? "DLL (Biblioteca Dinamica)" : "EXE (Ejecutable)") << "\n"
                  << " Entropia Promedio   : " << std::fixed << std::setprecision(2) << rep.overallEntropy << " / 8.0\n"
                  << " Secciones           : " << rep.sections.size() << "\n"
                  << " Punto de Entrada    : " << rep.entryPointSection << " (RVA: 0x" << std::hex << rep.entryPointRVA << std::dec << ")\n"
                  << " Firma Digital       : " << (rep.isSigned ? (rep.isSignatureValid ? "Valida y Confiable" : "Invalida / No Confiable") : "No Firmado") << "\n";
        
        if (!rep.signerSubject.empty()) {
            std::wcout << L" Emisor Certificado  : " << rep.signerSubject << L"\n";
        }
        if (!rep.detectedPacker.empty()) {
            std::cout << " Packer Detectado    : " << rep.detectedPacker << "\n";
        }

        std::cout << " Puntuacion de Riesgo: " << rep.heuristicScore << " / 100\n"
                  << "---------------------------------------------------------\n";

        if (!rep.anomalyReasons.empty()) {
            std::cout << "[!] Anomalías o Indicadores Heurísticos:\n";
            for (const auto& a : rep.anomalyReasons) {
                std::cout << "  - " << a << "\n";
            }
            std::cout << "\n";
        }

        if (!rep.suspiciousImports.empty()) {
            std::cout << "[!] APIs sospechosas detectadas (" << rep.suspiciousImports.size() << "):\n  ";
            for (const auto& api : rep.suspiciousImports) {
                std::cout << api << " ";
            }
            std::cout << "\n\n";
        }

        return rep.heuristicScore > 50 ? 2 : 0;
    }

    // 6. Escáner de Archivos (scan / quick / full)
    openguard::FileScanner scanner(sigDb);

    if (command == "scan") {
        if (argc < 3) {
            std::cerr << "[!] Error: Debe especificar la ruta a escanear.\n";
            return 1;
        }

        std::filesystem::path target = argv[2];
        std::cout << "[*] Iniciando escaneo en: " << target.string() << "\n";

        auto session = scanner.scanPath(target, openguard::ScanType::Custom, [](const openguard::ScanResult& res) {
            if (res.isThreat()) {
                std::cout << "[!] Amenaza detectada: " << res.filePath.string() << "\n";
            }
        });

        printSessionSummary(session);
        return session.threatsFound > 0 ? 2 : 0;
    }

    if (command == "quick") {
        std::cout << "[*] Iniciando analisis rapido de carpetas criticas...\n";

        std::vector<std::filesystem::path> quickPaths;
        const char* userProfile = std::getenv("USERPROFILE");
        const char* tempDir = std::getenv("TEMP");

        if (userProfile) {
            std::filesystem::path home(userProfile);
            quickPaths.push_back(home / "Downloads");
            quickPaths.push_back(home / "Desktop");
        }
        if (tempDir) {
            quickPaths.push_back(std::filesystem::path(tempDir));
        }

        auto session = scanner.scanPaths(quickPaths, openguard::ScanType::Quick, [](const openguard::ScanResult& res) {
            if (res.isThreat()) {
                std::cout << "[!] Amenaza en area critica: " << res.filePath.string() << "\n";
            }
        });

        printSessionSummary(session);
        return session.threatsFound > 0 ? 2 : 0;
    }

    std::cerr << "[!] Comando no reconocido: " << command << "\n";
    printHelp(argv[0]);
    return 1;
}
