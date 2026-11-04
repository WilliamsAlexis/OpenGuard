/**
 * @file main_cli.cpp
 * @brief Punto de entrada de la interfaz de consola (CLI) de OpenGuard.
 * @details Permite ejecutar análisis rápidos, completos, personalizados, auditorías de red,
 *          vulnerabilidades del sistema, análisis PE y gestión de cuarentena cifrada.
 */

#include "openguard/net_update.h"
#include "openguard/network_scan.h"
#include "openguard/history.h"
#include "openguard/paths.h"
#include "openguard/settings.h"
#include "openguard/pe_analyzer.h"
#include "openguard/quarantine.h"
#include "openguard/scanner.h"
#include "openguard/signatures.h"
#include "openguard/vuln_scan.h"

#include <windows.h>

#include <atomic>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifndef OPENGUARD_VERSION
#define OPENGUARD_VERSION "0.4.5"
#endif

namespace {

namespace fs = std::filesystem;
using openguard::paths::fromUtf8;
using openguard::paths::toUtf8;

constexpr int kExitOk = 0;
constexpr int kExitError = 1;
constexpr int kExitThreats = 2;

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
 */
void printHelp(const std::string& progName) {
    std::cout << "Uso: " << progName << " <comando> [opciones]\n\n"
              << "Comandos de Escaneo de Archivos:\n"
              << "  scan <ruta>             Analiza un archivo o directorio especifico.\n"
              << "  quick                   Analisis rapido: Descargas, Escritorio, Documentos, Temp e Inicio.\n"
              << "  full                    Analisis exhaustivo de todas las unidades fijas.\n"
              << "  pe <ruta_ejecutable>    Analisis estatico profundo de estructura PE y firma digital.\n"
              << "  Opcion para scan/quick/full:\n"
              << "    --quarantine          Aisla en la boveda cifrada las amenazas de riesgo alto o critico.\n\n"
              << "Comandos de Auditoria del Sistema:\n"
              << "  vuln                    Audita configuraciones de seguridad de Windows (UAC, SMBv1, Firewall).\n"
              << "  network                 Audita conexiones TCP activas, puertos C2 y archivo hosts.\n\n"
              << "Comandos de Cuarentena Cifrada:\n"
              << "  quarantine list         Lista todos los elementos aislados en la boveda.\n"
              << "  quarantine restore <id> Restaura un elemento a su ubicacion original.\n"
              << "  quarantine delete <id>  Destruye permanentemente un elemento con sobreescritura segura.\n\n"
              << "Base de Firmas y Servicio:\n"
              << "  stats                   Muestra metricas de la base de datos de firmas.\n"
              << "  update [archivo.json]   Importa firmas desde un JSON (por defecto signatures/hashes_index.json).\n"
              << "  update --online [url] [--auth-key K] [--name N]\n"
              << "                          Descarga por HTTPS un JSON de OpenGuard o una lista de hashes (uno por linea).\n"
              << "  status                  Estado del servicio de proteccion en tiempo real.\n"
              << "  logs [n]                Muestra las ultimas n lineas (20 por defecto) del registro del servicio.\n"
              << "  history [n]             Historial estructurado de detecciones y acciones (20 por defecto).\n\n"
              << "Otros Comandos:\n"
              << "  --help, -h              Muestra esta ayuda en pantalla.\n"
              << "  --version, -v           Informa la version de OpenGuard instalada.\n\n"
              << "Codigos de salida: 0 = sin amenazas, 1 = error, 2 = amenazas detectadas.\n\n";
}

const char* riskLevelName(openguard::RiskLevel level) {
    switch (level) {
        case openguard::RiskLevel::Clean:    return "Limpio";
        case openguard::RiskLevel::Low:      return "Bajo";
        case openguard::RiskLevel::Medium:   return "Medio";
        case openguard::RiskLevel::High:     return "Alto";
        case openguard::RiskLevel::Critical: return "Critico";
    }
    return "Desconocido";
}

/**
 * @brief Lee una variable de entorno como ruta (vacía si no existe).
 */
fs::path envPath(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (size == 0) return {};
    std::wstring value(size, L'\0');
    const DWORD written = GetEnvironmentVariableW(name, value.data(), size);
    value.resize(written);
    return fs::path(value);
}

/**
 * @brief Abre la base de firmas, la inicializa con EICAR y el índice JSON incluido.
 */
std::shared_ptr<openguard::SignatureDB> openDatabase() {
    const fs::path dbPath = openguard::paths::databasePath();
    auto db = std::make_shared<openguard::SignatureDB>(dbPath);

    if (!db->isOpen()) {
        std::cerr << "[!] Advertencia: no se pudo abrir la base de firmas en " << toUtf8(dbPath)
                  << ". Solo se aplicara la heuristica.\n";
        return db;
    }

    if (db->isReadOnly()) {
        std::cerr << "[!] La base de firmas es de solo lectura (ejecute como Administrador para actualizarla).\n";
        return db;
    }

    db->seedEicar();
    size_t inserted = 0, skipped = 0;
    db->importFromJson(openguard::paths::signaturesDir() / "hashes_index.json", inserted, skipped);
    return db;
}

/**
 * @brief Construye la configuración del escáner excluyendo los datos propios (cuarentena, logs).
 */
openguard::ScannerConfig makeScannerConfig() {
    openguard::ScannerConfig cfg;
    cfg.excludedPaths.push_back(openguard::paths::dataDir());
    // Las reglas YARA y los binarios de OpenGuard contienen las cadenas que buscan: se excluyen para no autodetectarse
    cfg.excludedPaths.push_back(openguard::paths::executableDir());
    cfg.excludedPaths.push_back(openguard::paths::signaturesDir());
    cfg.yaraRulesDir = openguard::paths::signaturesDir() / "yara_rules";
    cfg.yaraUpdatesDir = openguard::paths::rulesUpdateDir();
    const auto prot = openguard::ProtectionSettings::load(); // límite de CPU y exclusiones del usuario
    cfg.threadCount = prot.threadCount();
    for (const auto& ex : prot.exclusions) cfg.excludedPaths.push_back(ex);
    return cfg;
}

/**
 * @brief Callback de progreso: alerta de amenazas y contador de archivos analizados.
 */
std::function<void(const openguard::ScanResult&)> makeProgressCallback() {
    auto counter = std::make_shared<std::atomic<size_t>>(0);
    return [counter](const openguard::ScanResult& res) {
        const size_t n = ++(*counter);
        if (res.isThreat()) {
            std::cout << "\r" << std::string(60, ' ') << "\r"
                      << "[!] Amenaza detectada: " << toUtf8(res.filePath) << "\n";
        }
        if (n % 500 == 0) {
            std::cout << "\r[*] Archivos procesados: " << n << std::flush;
        }
    };
}

/**
 * @brief Presenta un resumen final formateado de la sesion de analisis completada.
 */
void printSessionSummary(const openguard::ScanSessionStats& session) {
    std::cout << "\r" << std::string(60, ' ') << "\r"
              << "\n---------------------------------------------------------\n"
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
            if (!res.isThreat()) continue;
            std::cout << "\n  [!] Elemento: " << toUtf8(res.filePath) << "\n"
                      << "      Nivel de Riesgo : " << riskLevelName(res.riskLevel)
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
        std::cout << "\n";
    } else {
        std::cout << "\n[+] El analisis no encontro amenazas conocidas ni anomalias.\n\n";
    }
}

/**
 * @brief Aisla en cuarentena las amenazas de riesgo alto o critico de una sesion.
 */
void quarantineThreats(const openguard::ScanSessionStats& session) {
    openguard::QuarantineVault vault(openguard::paths::quarantineDir());
    size_t isolated = 0, failed = 0;

    for (const auto& res : session.results) {
        if (res.riskLevel != openguard::RiskLevel::High && res.riskLevel != openguard::RiskLevel::Critical) continue;

        const auto& first = res.threats.front();
        auto item = vault.quarantineFile(res.filePath, first.name, first.severity, res.sha256);
        if (item) {
            ++isolated;
            std::cout << "[+] Aislado (id " << item->qid << "): " << toUtf8(res.filePath) << "\n";
        } else {
            ++failed;
            std::cout << "[!] No se pudo aislar: " << toUtf8(res.filePath)
                      << " (en uso o sin permisos; ejecute como Administrador)\n";
        }
    }
    std::cout << "\nCuarentena: " << isolated << " aislados, " << failed << " con error.\n\n";
}

/**
 * @brief Ejecuta un escaneo y gestiona el resumen y la cuarentena opcional.
 */
int runScan(openguard::FileScanner& scanner,
            const std::vector<fs::path>& targets,
            openguard::ScanType type,
            bool autoQuarantine) {
    auto session = scanner.scanPaths(targets, type, makeProgressCallback());
    printSessionSummary(session);

    if (autoQuarantine && session.threatsFound > 0) {
        quarantineThreats(session);
    }
    return session.threatsFound > 0 ? kExitThreats : kExitOk;
}

/**
 * @brief Consulta el SCM y muestra si el servicio de protección está instalado y en ejecución.
 */
int showServiceStatus() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::cerr << "[!] No se pudo consultar el Administrador de servicios de Windows.\n";
        return kExitError;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"OpenGuardService", SERVICE_QUERY_STATUS);
    if (!svc) {
        std::cout << "Servicio de proteccion en tiempo real: NO INSTALADO\n"
                  << "  Para instalarlo (como Administrador): openguard_service.exe --install\n";
        CloseServiceHandle(scm);
        return kExitOk;
    }

    SERVICE_STATUS status{};
    const char* text = "DESCONOCIDO";
    if (QueryServiceStatus(svc, &status)) {
        switch (status.dwCurrentState) {
            case SERVICE_RUNNING:       text = "ACTIVO (protegiendo en tiempo real)"; break;
            case SERVICE_STOPPED:       text = "DETENIDO"; break;
            case SERVICE_START_PENDING: text = "INICIANDO"; break;
            case SERVICE_STOP_PENDING:  text = "DETENIENDO"; break;
            default: break;
        }
    }
    std::cout << "Servicio de proteccion en tiempo real: " << text << "\n";

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return kExitOk;
}

/**
 * @brief Imprime las últimas líneas del registro del servicio.
 */
int showLogs(size_t lines) {
    const fs::path logPath = openguard::paths::logsDir() / "service.log";
    std::ifstream in(logPath, std::ios::binary);
    if (!in.is_open()) {
        std::cout << "Aun no hay registro del servicio (" << toUtf8(logPath) << ").\n";
        return kExitOk;
    }

    std::vector<std::string> all;
    std::string line;
    while (std::getline(in, line)) all.push_back(line);

    const size_t start = all.size() > lines ? all.size() - lines : 0;
    for (size_t i = start; i < all.size(); ++i) std::cout << all[i] << "\n";
    return kExitOk;
}

/**
 * @brief Análisis estático PE y salida formateada.
 */
int runPeAnalysis(const fs::path& target) {
    std::cout << "[*] Analizando estructura binaria PE de: " << toUtf8(target) << "\n";

    openguard::PEAnalyzer peAnalyzer;
    auto rep = peAnalyzer.analyze(target);

    if (!rep.isValidPE) {
        std::cout << "[!] El archivo no es un ejecutable PE de Windows valido.\n";
        return kExitError;
    }

    std::cout << "\n---------------------------------------------------------\n"
              << "              Reporte de Analisis Estatico PE            \n"
              << "---------------------------------------------------------\n"
              << " Arquitectura        : " << (rep.is64Bit ? "64-bit (PE32+)" : "32-bit (PE32)") << "\n"
              << " Tipo de Binario     : " << (rep.isDLL ? "DLL (Biblioteca Dinamica)" : "EXE (Ejecutable)") << "\n"
              << " Entropia Promedio   : " << std::fixed << std::setprecision(2) << rep.overallEntropy << " / 8.0\n"
              << " Secciones           : " << rep.sections.size() << "\n"
              << " Punto de Entrada    : " << rep.entryPointSection << " (RVA: 0x" << std::hex << rep.entryPointRVA << std::dec << ")\n"
              << " DLLs importadas     : " << rep.importedDLLs.size() << "\n"
              << " Firma Digital       : " << (rep.isSigned ? (rep.isSignatureValid ? "Valida y Confiable" : "Invalida / No Confiable") : "No Firmado") << "\n";

    if (!rep.signerSubject.empty()) {
        std::cout << " Emisor Certificado  : " << toUtf8(fs::path(rep.signerSubject)) << "\n";
    }
    if (!rep.detectedPacker.empty()) {
        std::cout << " Packer Detectado    : " << rep.detectedPacker << "\n";
    }

    std::cout << " Puntuacion de Riesgo: " << rep.heuristicScore << " / 100\n"
              << "---------------------------------------------------------\n";

    if (!rep.anomalyReasons.empty()) {
        std::cout << "[!] Anomalias o Indicadores Heuristicos:\n";
        for (const auto& a : rep.anomalyReasons) {
            std::cout << "  - " << a << "\n";
        }
        std::cout << "\n";
    }

    if (!rep.suspiciousImports.empty()) {
        std::cout << "[i] APIs sensibles importadas (" << rep.suspiciousImports.size() << "):\n  ";
        for (const auto& api : rep.suspiciousImports) {
            std::cout << api << " ";
        }
        std::cout << "\n\n";
    }

    return rep.heuristicScore > 50 ? kExitThreats : kExitOk;
}

int runVulnAudit() {
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
    return report.totalRiskScore > 50 ? kExitThreats : kExitOk;
}

int runNetworkAudit() {
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
        return kExitThreats;
    }
    std::cout << "[+] No se encontraron conexiones a puertos C2 ni secuestros de red.\n\n";
    return kExitOk;
}

int runQuarantine(const std::vector<std::string>& args) {
    openguard::QuarantineVault vault(openguard::paths::quarantineDir());

    if (args.size() >= 3) {
        const std::string& sub = args[2];
        if (sub == "list") {
            auto items = vault.listItems();
            std::cout << "Boveda de Cuarentena (" << items.size() << " elementos resguardados):\n";
            for (const auto& item : items) {
                std::cout << "  [" << item.qid << "] " << item.threatName << " (" << item.severity << ")\n"
                          << "      Ruta Original : " << toUtf8(item.originalPath) << "\n"
                          << "      Fecha         : " << item.quarantinedAt << "\n"
                          << "      SHA-256       : " << item.sha256 << "\n\n";
            }
            return kExitOk;
        }
        if (sub == "restore" && args.size() >= 4) {
            const bool ok = vault.restoreFile(args[3]);
            std::cout << (ok ? "[+] Archivo restaurado exitosamente a su ruta original.\n"
                             : "[!] Fallo al restaurar (id inexistente, archivo ya existente en destino o integridad invalida).\n");
            return ok ? kExitOk : kExitError;
        }
        if (sub == "delete" && args.size() >= 4) {
            const bool ok = vault.deletePermanently(args[3]);
            std::cout << (ok ? "[+] Archivo purgado de la boveda con sobreescritura segura.\n"
                             : "[!] Fallo al eliminar el elemento de la cuarentena.\n");
            return ok ? kExitOk : kExitError;
        }
    }

    std::cout << "Uso de cuarentena:\n"
              << "  quarantine list\n"
              << "  quarantine restore <id>\n"
              << "  quarantine delete <id>\n";
    return kExitOk;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8); // Rutas con acentos y símbolos se muestran correctamente

    // Los argumentos se convierten a UTF-8 una sola vez; las rutas se reconstruyen con fromUtf8.
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) args.push_back(toUtf8(fs::path(argv[i])));

    printBanner();

    if (args.size() < 2) {
        printHelp("openguard_cli");
        return kExitOk;
    }

    const std::string& command = args[1];

    if (command == "--help" || command == "-h") {
        printHelp("openguard_cli");
        return kExitOk;
    }

    if (command == "--version" || command == "-v") {
        std::cout << "OpenGuard version " OPENGUARD_VERSION " (Edicion Nativa Windows C++20)\n";
        return kExitOk;
    }

    try {
        // Comandos que no requieren la base de firmas
        if (command == "vuln") return runVulnAudit();
        if (command == "network") return runNetworkAudit();
        if (command == "quarantine") return runQuarantine(args);
        if (command == "status") return showServiceStatus();
        if (command == "history") {
            size_t n = 20;
            if (args.size() >= 3) {
                try { n = std::stoul(args[2]); } catch (...) { n = 20; }
            }
            openguard::ThreatHistory history(openguard::paths::dataDir() / "history.db");
            const auto events = history.recent(n);
            if (events.empty()) {
                std::cout << "El historial esta vacio.\n";
                return kExitOk;
            }
            for (const auto& e : events) {
                std::cout << e.timestamp << " [" << e.level << "] " << e.kind << ": " << e.threat
                          << " | " << e.action << " | " << e.path << "\n";
            }
            return kExitOk;
        }
        if (command == "logs") {
            size_t n = 20;
            if (args.size() >= 3) {
                try { n = std::stoul(args[2]); } catch (...) { n = 20; }
            }
            return showLogs(n);
        }
        if (command == "pe") {
            if (args.size() < 3) {
                std::cerr << "[!] Error: Debe indicar la ruta del ejecutable PE.\n";
                return kExitError;
            }
            return runPeAnalysis(fromUtf8(args[2]));
        }

        auto sigDb = openDatabase();

        if (command == "stats") {
            auto stats = sigDb->getStats();
            std::cout << "Estado de la Base de Firmas (" << toUtf8(openguard::paths::databasePath()) << "):\n"
                      << "  Total de firmas cargadas: " << stats.totalSignatures << "\n";
            for (const auto& [sev, count] : stats.bySeverity) {
                std::cout << "    - " << sev << ": " << count << "\n";
            }
            return kExitOk;
        }

        if (command == "update" && args.size() >= 3 && args[2] == "--online") {
            // update --online [url] [--auth-key CLAVE] [--name NOMBRE]
            std::string url = "https://raw.githubusercontent.com/WilliamsAlexis/OpenGuard/main/signatures/hashes_index.json";
            std::string authKey, name = "Imported.HashList";
            for (size_t i = 3; i < args.size(); ++i) {
                if (args[i] == "--auth-key" && i + 1 < args.size()) authKey = args[++i];
                else if (args[i] == "--name" && i + 1 < args.size()) name = args[++i];
                else url = args[i];
            }

            std::cout << "[*] Descargando " << url << "\n    (solo se envia una peticion GET; ver PRIVACY.md)\n";
            std::string body, err;
            if (!openguard::net::httpsGet(url, body, err, 64u * 1024u * 1024u, authKey)) {
                std::cerr << "[!] Descarga fallida: " << err << "\n";
                return kExitError;
            }

            size_t inserted = 0, skipped = 0;
            const size_t firstChar = body.find_first_not_of(" \t\r\n\xEF\xBB\xBF");
            const bool isJson = firstChar != std::string::npos && body[firstChar] == '{';
            bool ok = false;
            if (isJson) {
                const fs::path tmp = openguard::paths::dataDir() / "download.json";
                { std::ofstream out(tmp, std::ios::binary); out << body; }
                ok = sigDb->importFromJson(tmp, inserted, skipped);
                std::error_code ec;
                fs::remove(tmp, ec);
            } else {
                ok = sigDb->importHashList(body, name, "online", inserted, skipped);
            }
            if (!ok) {
                std::cerr << "[!] No se pudo importar lo descargado (formato invalido o base de solo lectura: ejecute como Administrador).\n";
                return kExitError;
            }
            std::cout << "[+] Actualizacion completada: " << inserted << " firmas nuevas, " << skipped << " omitidas.\n";
            return kExitOk;
        }

        if (command == "update") {
            const fs::path jsonPath = args.size() >= 3
                ? fromUtf8(args[2])
                : openguard::paths::signaturesDir() / "hashes_index.json";
            size_t inserted = 0, skipped = 0;
            if (!sigDb->importFromJson(jsonPath, inserted, skipped)) {
                std::cerr << "[!] No se pudo importar " << toUtf8(jsonPath)
                          << " (archivo inexistente, JSON invalido o base de solo lectura).\n";
                return kExitError;
            }
            std::cout << "[+] Importacion completada: " << inserted << " firmas nuevas, "
                      << skipped << " omitidas (duplicadas o invalidas).\n";
            return kExitOk;
        }

        // Comandos de escaneo de archivos
        bool autoQuarantine = false;
        std::vector<std::string> positional;
        for (size_t i = 2; i < args.size(); ++i) {
            if (args[i] == "--quarantine") autoQuarantine = true;
            else positional.push_back(args[i]);
        }

        openguard::FileScanner scanner(sigDb, makeScannerConfig());

        if (command == "scan") {
            if (positional.empty()) {
                std::cerr << "[!] Error: Debe especificar la ruta a escanear.\n";
                return kExitError;
            }
            const fs::path target = fromUtf8(positional[0]);
            std::error_code ec;
            if (!fs::exists(target, ec)) {
                std::cerr << "[!] Error: la ruta no existe: " << toUtf8(target) << "\n";
                return kExitError;
            }
            std::cout << "[*] Iniciando escaneo en: " << toUtf8(target) << "\n";
            return runScan(scanner, {target}, openguard::ScanType::Custom, autoQuarantine);
        }

        if (command == "quick") {
            std::cout << "[*] Iniciando analisis rapido de carpetas criticas...\n";

            std::vector<fs::path> quickPaths;
            const fs::path profile = envPath(L"USERPROFILE");
            if (!profile.empty()) {
                quickPaths.push_back(profile / L"Downloads");
                quickPaths.push_back(profile / L"Desktop");
                quickPaths.push_back(profile / L"Documents");
            }
            const fs::path temp = envPath(L"TEMP");
            if (!temp.empty()) quickPaths.push_back(temp);

            const fs::path appData = envPath(L"APPDATA");
            if (!appData.empty()) {
                quickPaths.push_back(appData / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            }
            const fs::path programData = envPath(L"ProgramData");
            if (!programData.empty()) {
                quickPaths.push_back(programData / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup");
            }

            return runScan(scanner, quickPaths, openguard::ScanType::Quick, autoQuarantine);
        }

        if (command == "full") {
            const auto drives = openguard::FileScanner::getFixedDrives();
            if (drives.empty()) {
                std::cerr << "[!] No se encontraron unidades fijas para analizar.\n";
                return kExitError;
            }
            std::cout << "[*] Iniciando analisis completo de:";
            for (const auto& d : drives) std::cout << " " << toUtf8(d);
            std::cout << "\n    Esto puede tardar bastante tiempo...\n";
            return runScan(scanner, drives, openguard::ScanType::Full, autoQuarantine);
        }

        std::cerr << "[!] Comando no reconocido: " << command << "\n";
        printHelp("openguard_cli");
        return kExitError;

    } catch (const std::exception& e) {
        std::cerr << "[!] Error inesperado: " << e.what() << "\n";
        return kExitError;
    }
}
