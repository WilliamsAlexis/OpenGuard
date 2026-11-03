/**
 * @file service_main.cpp
 * @brief Servicio de Windows para la protección en tiempo real de OpenGuard.
 * @details Interactúa con el Service Control Manager (SCM) y ejecuta el motor de protección:
 *          - Monitoreo de carpetas de riesgo (Descargas, Escritorio, Documentos, Temp) con
 *            ReadDirectoryChangesW y análisis de cada archivo nuevo o modificado.
 *          - Escaneo automático de unidades extraíbles (USB) al conectarse.
 *          - Cuarentena automática de amenazas confirmadas (coincidencia de firma o riesgo crítico).
 *          - Registro de eventos en %ProgramData%\OpenGuard\logs\service.log.
 *
 *          Modos: sin argumentos (lo inicia el SCM), --install, --uninstall, --console (depuración).
 */

#include "openguard/crypto_utils.h"
#include "openguard/history.h"
#include "openguard/isolated_scan.h"
#include "openguard/settings.h"
#include "openguard/paths.h"
#include "openguard/quarantine.h"
#include "openguard/realtime_monitor.h"
#include "openguard/scanner.h"
#include "openguard/signatures.h"

#include <windows.h>

#include <atomic>
#include <cstring>
#include <cstdint>
#include <cwctype>
#include <deque>
#include <exception>
#include <iterator>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

namespace fs = std::filesystem;

constexpr wchar_t SERVICE_NAME[] = L"OpenGuardService";
constexpr wchar_t SERVICE_DISPLAY_NAME[] = L"OpenGuard Antivirus Real-Time Protection";
constexpr wchar_t SERVICE_DESCRIPTION[] =
    L"Protege el equipo en tiempo real: analiza archivos nuevos, unidades USB y aísla amenazas confirmadas.";

SERVICE_STATUS        g_serviceStatus{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE                g_stopEvent = nullptr;
bool                  g_consoleMode = false;

// ---------------------------------------------------------------------------------------------
// Registro de eventos
// ---------------------------------------------------------------------------------------------

class Logger {
public:
    void write(const std::string& level, const std::string& message) {
        std::lock_guard<std::mutex> lock(m_mutex);

        const auto now = std::chrono::system_clock::now();
        const std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::tm local{};
        localtime_s(&local, &tt);
        char stamp[32]{};
        std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local);

        const std::string line = std::string(stamp) + " [" + level + "] " + message + "\n";

        const fs::path logPath = openguard::paths::logsDir() / "service.log";
        rotateIfNeeded(logPath);
        std::ofstream out(logPath, std::ios::app | std::ios::binary);
        if (out.is_open()) out << line;

        if (g_consoleMode) std::cout << line << std::flush;
    }

private:
    static void rotateIfNeeded(const fs::path& logPath) {
        std::error_code ec;
        constexpr std::uintmax_t kMaxBytes = 5 * 1024 * 1024;
        if (fs::exists(logPath, ec) && fs::file_size(logPath, ec) > kMaxBytes) {
            fs::path old = logPath;
            old += ".1";
            fs::remove(old, ec);
            fs::rename(logPath, old, ec);
        }
    }

    std::mutex m_mutex;
};

Logger g_log;

// ---------------------------------------------------------------------------------------------
// Motor de protección
// ---------------------------------------------------------------------------------------------

class ProtectionEngine {
public:
    bool start() {
        loadSettings();
        m_db = std::make_shared<openguard::SignatureDB>(openguard::paths::databasePath());
        if (!m_db->isOpen()) {
            g_log.write("ERROR", "No se pudo abrir la base de firmas: " +
                                     openguard::paths::toUtf8(openguard::paths::databasePath()));
            return false;
        }

        m_db->seedEicar();
        size_t inserted = 0, skipped = 0;
        const fs::path jsonPath = openguard::paths::signaturesDir() / "hashes_index.json";
        if (m_db->importFromJson(jsonPath, inserted, skipped)) {
            g_log.write("INFO", "Firmas cargadas desde JSON: " + std::to_string(inserted) +
                                    " nuevas, " + std::to_string(skipped) + " omitidas");
        } else {
            g_log.write("WARN", "No se pudo importar " + openguard::paths::toUtf8(jsonPath));
        }
        g_log.write("INFO", "Base de firmas lista (" + std::to_string(m_db->getStats().totalSignatures) + " firmas)");

        openguard::ScannerConfig cfg;
        cfg.threadCount = m_set.threadCount();   // Límite de CPU configurable (Configuración > Rendimiento)
        cfg.lowPriority = true;                   // El análisis en segundo plano no compite con el usuario
        for (const auto& ex : m_set.exclusions) cfg.excludedPaths.push_back(ex);
        cfg.excludedPaths.push_back(openguard::paths::dataDir());
        cfg.excludedPaths.push_back(openguard::paths::executableDir());
        cfg.excludedPaths.push_back(openguard::paths::signaturesDir());
        cfg.yaraRulesDir = openguard::paths::signaturesDir() / "yara_rules";

        // Análisis de contenido en un proceso aislado (token restringido, integridad baja, Job Object).
        // Si el trabajador no está disponible o no puede iniciarse, se usa el análisis en proceso como respaldo.
        if (m_set.isolatedScan) {
            openguard::IsolatedScanner::Options opts;
            opts.workerExe = openguard::paths::executableDir() / "openguard_worker.exe";
            auto isolated = std::make_shared<openguard::IsolatedScanner>(m_db, opts);
            if (isolated->available()) {
                openguard::ScannerConfig fbCfg = cfg;
                fbCfg.threadCount = 1;
                auto fallback = std::make_shared<openguard::FileScanner>(m_db, fbCfg);
                cfg.customAnalyzer = [isolated, fallback](const fs::path& p) -> openguard::ScanResult {
                    if (auto r = isolated->scan(p)) return *r;
                    return fallback->scanFile(p);
                };
                m_isolated = isolated;

                // El trabajador no debe tener red: si lo explotara un archivo malicioso no podría exfiltrar ni descargar
                std::string fwDetail;
                m_networkBlocked = openguard::IsolatedScanner::ensureNetworkBlock(opts.workerExe, fwDetail);
                if (m_networkBlocked) {
                    g_log.write("INFO", "Analisis aislado activo (bajo privilegio, sin acceso a red)");
                } else {
                    g_log.write("WARN", "Analisis aislado activo, pero NO se pudo bloquear la red del trabajador: " + fwDetail);
                    hist("system", "WARN", {}, "Trabajador sin bloqueo de red", fwDetail);
                }
                writeIsolationStatus("full");
            } else {
                g_log.write("WARN", "openguard_worker.exe no encontrado: el analisis se hace dentro del servicio");
                hist("system", "WARN", {}, "Analisis aislado no disponible", "falta openguard_worker.exe");
                writeIsolationStatus("missing");
            }
        } else {
            writeIsolationStatus("off");
        }
        m_config = cfg;
        m_scanner = std::make_unique<openguard::FileScanner>(m_db, cfg);
        m_vault = std::make_unique<openguard::QuarantineVault>(openguard::paths::quarantineDir());
        m_history = std::make_unique<openguard::ThreatHistory>(openguard::paths::dataDir() / "history.db");
        m_history->purgeOlderThan(365); // mantenimiento: conserva un año de historial
        g_log.write("INFO", "Motor YARA: " + std::to_string(m_scanner->yaraRuleCount()) + " reglas cargadas");

        const auto dirs = collectWatchDirectories(m_set.scanDownloads);
        if (!m_set.scanDownloads) g_log.write("INFO", "Analisis de archivos descargados desactivado en la configuracion");
        if (m_enableDecoys) createDecoys(dirs);
        const bool started = m_monitor.start(dirs, [this](const fs::path& p) { onFileChanged(p); });
        g_log.write(started ? "INFO" : "ERROR",
                    started ? "Proteccion en tiempo real activa en " + std::to_string(m_monitor.watchedCount()) + " carpetas"
                            : "No se pudo iniciar la vigilancia de carpetas");

        // Registrar las unidades extraíbles ya conectadas sin escanearlas al arrancar
        for (const auto& drive : currentRemovableDrives()) m_knownRemovable.insert(drive);
        return started;
    }

    void stop() {
        if (m_schedScanner) m_schedScanner->cancelScan(); // un análisis programado en curso se interrumpe
        if (m_scheduleThread.joinable()) m_scheduleThread.join();
        m_monitor.stop();
        removeDecoys();
        for (auto& t : m_usbThreads) {
            if (t.joinable()) t.join();
        }
        m_usbThreads.clear();
        g_log.write("INFO", "Proteccion en tiempo real detenida");
    }

    /// Llamada periódica: detecta unidades extraíbles recién conectadas.
    void poll() {
        checkDecoys();
        checkSchedule();
        if (m_isolated && m_isolated->degraded() && !m_degradedLogged) {
            m_degradedLogged = true;
            g_log.write("WARN", "Analisis aislado en modo degradado: no se pudo aplicar el token restringido (solo Job Object)");
            hist("system", "WARN", {}, "Analisis aislado degradado", "sin token restringido");
            writeIsolationStatus("degraded");
        }
        const std::set<wchar_t> current = currentRemovableDrives();
        for (wchar_t letter : current) {
            if (m_knownRemovable.insert(letter).second && shouldAutoScanUsb()) {
                const fs::path root = std::wstring{letter, L':', L'\\'};
                g_log.write("INFO", "Unidad extraible detectada: " + openguard::paths::toUtf8(root) + " - iniciando analisis");
                m_usbThreads.emplace_back([this, root]() { scanRemovable(root); });
            }
        }
        // Olvidar unidades retiradas para volver a analizarlas si se reconectan
        for (auto it = m_knownRemovable.begin(); it != m_knownRemovable.end();) {
            it = current.count(*it) ? std::next(it) : m_knownRemovable.erase(it);
        }
    }

private:
    static std::set<wchar_t> currentRemovableDrives() {
        std::set<wchar_t> result;
        const DWORD mask = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if ((mask & (1u << i)) == 0) continue;
            const wchar_t root[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', L'\0' };
            if (GetDriveTypeW(root) == DRIVE_REMOVABLE) result.insert(static_cast<wchar_t>(L'A' + i));
        }
        return result;
    }

    /// Carpetas donde el malware suele aterrizar: perfiles de usuario y Temp del sistema.
    static std::vector<fs::path> collectWatchDirectories(bool includeDownloads) {
        std::vector<fs::path> dirs;
        std::error_code ec;

        wchar_t sysDrive[MAX_PATH]{};
        DWORD n = GetEnvironmentVariableW(L"SystemDrive", sysDrive, MAX_PATH);
        const fs::path usersRoot = fs::path(n ? std::wstring(sysDrive, n) : std::wstring(L"C:")) / L"\\Users";

        for (fs::directory_iterator it(usersRoot, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec)) {
            std::error_code e2;
            if (!it->is_directory(e2)) continue;
            const fs::path profile = it->path();
            std::vector<const wchar_t*> subs = { L"Desktop", L"Documents", L"AppData\\Local\\Temp" };
            if (includeDownloads) subs.insert(subs.begin(), L"Downloads"); // Configuración: "Analizar archivos descargados"
            for (const wchar_t* sub : subs) {
                const fs::path candidate = profile / sub;
                if (fs::is_directory(candidate, e2)) dirs.push_back(candidate);
            }
        }

        wchar_t winDir[MAX_PATH]{};
        n = GetEnvironmentVariableW(L"SystemRoot", winDir, MAX_PATH);
        if (n) {
            const fs::path winTemp = fs::path(std::wstring(winDir, n)) / L"Temp";
            if (fs::is_directory(winTemp, ec)) dirs.push_back(winTemp);
        }
        return dirs;
    }

    static bool isIgnoredExtension(const fs::path& p) {
        static const std::unordered_set<std::wstring> kIgnored = {
            L".tmp", L".log", L".etl", L".crdownload", L".part", L".partial", L".db-journal", L".db-wal", L".db-shm"
        };
        std::wstring ext = p.extension().wstring();
        for (auto& c : ext) c = static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
        return kIgnored.count(ext) > 0;
    }

    static bool isInside(const fs::path& path, const fs::path& dir) {
        const fs::path rel = path.lexically_relative(dir);
        return !rel.empty() && *rel.begin() != "..";
    }

    /// true si la aplicación (GUI) está abierta: ella pregunta al usuario cuando se conecta una unidad.
    static bool guiIsRunning() {
        HANDLE h = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\OpenGuardGuiRunning");
        if (!h) return false;
        CloseHandle(h);
        return true;
    }

    /// Modo "auto": el servicio analiza sin preguntar. Modo "ask": pregunta la GUI; si no está abierta, el servicio
    /// analiza igualmente para que una unidad infectada nunca quede sin revisar.
    bool shouldAutoScanUsb() const {
        if (m_set.usbMode == "off") return false;
        if (m_set.usbMode == "auto") return true;
        return !guiIsRunning();
    }

    /// Ajustes editables desde la GUI (config.ini en la carpeta de datos de OpenGuard)
    void loadSettings() {
        m_set = openguard::ProtectionSettings::load();
        m_autoQuarantine = m_set.autoQuarantine;
        m_enableDecoys = m_set.decoys;
        m_scanUsb = m_set.scanUsb;
        g_log.write("INFO", std::string("Ajustes: cuarentena automatica=") + (m_autoQuarantine ? "si" : "no") +
                                ", senuelos=" + (m_enableDecoys ? "si" : "no") + ", analisis USB=" + (m_scanUsb ? "si" : "no") +
                                ", CPU=" + std::to_string(m_set.cpuPercent) + "%, exclusiones=" + std::to_string(m_set.exclusions.size()));
    }

    /// Registra un evento en el historial estructurado (además del log de texto).
    void hist(const char* kind, const char* level, const std::string& path, const std::string& threat,
              const std::string& action, const std::string& sha = {}, const std::string& details = {}) {
        if (!m_history) return;
        openguard::HistoryEvent e;
        e.kind = kind;
        e.level = level;
        e.path = path;
        e.threat = threat;
        e.action = action;
        e.sha256 = sha;
        e.details = details;
        m_history->record(e);
    }

    openguard::ProtectionSettings m_set;
    std::shared_ptr<openguard::IsolatedScanner> m_isolated;
    bool m_degradedLogged{false};
    bool m_networkBlocked{false};

    // ----------------------------------------------------------------- análisis programados

    static std::wstring statusIniPath() { return (openguard::paths::dataDir() / L"status.ini").wstring(); }

    std::time_t readLastScheduledRun() const {
        wchar_t buf[64]{};
        GetPrivateProfileStringW(L"schedule", L"last_run", L"", buf, 64, statusIniPath().c_str());
        const std::wstring w(buf);
        return openguard::parseLocalStamp(std::string(w.begin(), w.end()));
    }

    void writeLastScheduledRun(std::time_t t) const {
        const std::string s = openguard::formatLocalStamp(t);
        const std::wstring w(s.begin(), s.end());
        WritePrivateProfileStringW(L"schedule", L"last_run", w.c_str(), statusIniPath().c_str());
    }

    /// Se invoca cada ~5 s: lanza el análisis programado cuando corresponde (con puesta al día si el equipo estaba apagado).
    void checkSchedule() {
        if (!m_set.schedule.enabled || m_scheduleRunning) return;

        const std::time_t now = std::time(nullptr);
        const std::time_t last = readLastScheduledRun();
        if (last == 0) { // primera vez: se fija la referencia sin ejecutar nada en este instante
            writeLastScheduledRun(now);
            return;
        }
        if (!openguard::scheduleIsDue(m_set.schedule, now, last)) return;

        writeLastScheduledRun(now); // se anota ya, para no relanzarlo mientras corre
        startScheduledScan();
    }

    void startScheduledScan() {
        if (m_scheduleThread.joinable()) m_scheduleThread.join(); // el anterior ya terminó (m_scheduleRunning == false)
        m_scheduleRunning = true;

        const bool full = (m_set.schedule.type == "full");
        openguard::ScannerConfig cfg = m_config;
        cfg.precount = false;
        m_schedScanner = std::make_shared<openguard::FileScanner>(m_db, cfg);
        g_log.write("INFO", std::string("Analisis programado iniciado (") + (full ? "completo" : "rapido") + ")");
        hist("scan", "INFO", {}, full ? "Analisis programado completo" : "Analisis programado rapido", "iniciado");

        auto scanner = m_schedScanner;
        m_scheduleThread = std::thread([this, scanner, full]() {
            try {
                const std::vector<fs::path> targets = full ? openguard::FileScanner::getFixedDrives() : collectWatchDirectories(true);
                auto session = scanner->scanPaths(targets, full ? openguard::ScanType::Full : openguard::ScanType::Quick);
                for (const auto& r : session.results) {
                    if (r.isThreat()) handleResult(r);
                }
                g_log.write("INFO", "Analisis programado completado: " + std::to_string(session.filesScanned) + " archivos, " +
                                        std::to_string(session.threatsFound) + " amenazas");
                hist("scan", "INFO", {}, full ? "Analisis programado completo" : "Analisis programado rapido",
                     "completado", {}, std::to_string(session.filesScanned) + " archivos, " + std::to_string(session.threatsFound) +
                                            " amenazas, " + std::to_string(session.duration.count() / 1000) + " s");
            } catch (const std::exception& e) {
                g_log.write("ERROR", std::string("Analisis programado fallo: ") + e.what());
            }
            m_scheduleRunning = false;
        });
    }

    std::thread m_scheduleThread;
    std::shared_ptr<openguard::FileScanner> m_schedScanner;
    std::atomic<bool> m_scheduleRunning{false};

    /// Estado del aislamiento para la GUI: %ProgramData%\OpenGuard\status.ini
    void writeIsolationStatus(const char* mode) {
        const std::wstring ini = (openguard::paths::dataDir() / L"status.ini").wstring();
        const std::wstring m(mode, mode + std::strlen(mode));
        WritePrivateProfileStringW(L"isolation", L"mode", m.c_str(), ini.c_str());
        WritePrivateProfileStringW(L"isolation", L"network_block", m_networkBlocked ? L"1" : L"0", ini.c_str());
    }
    std::unique_ptr<openguard::ThreatHistory> m_history;
    bool m_autoQuarantine{true};
    bool m_enableDecoys{true};
    bool m_scanUsb{true};

    // ----------------------------------------------------------------- anti-ransomware

    struct Decoy {
        fs::path path;
        std::string sha256;
        bool alerted{false};
    };

    /// Crea archivos señuelo ocultos en Documentos y Escritorio. El ransomware cifra todo lo que
    /// encuentra: si un señuelo se modifica, se elimina o se renombra, se genera una alerta.
    void createDecoys(const std::vector<fs::path>& watchedDirs) {
        static const char kContent[] =
            "OpenGuard decoy file. Do not modify or delete this file.\r\n"
            "Archivo senuelo de OpenGuard. No lo modifique ni lo elimine: sirve para detectar ransomware.\r\n";

        for (const auto& dir : watchedDirs) {
            const std::wstring leaf = dir.filename().wstring();
            if (leaf != L"Documents" && leaf != L"Desktop") continue;

            Decoy d;
            d.path = dir / L"~OpenGuard_decoy.docx";
            std::error_code ec;
            SetFileAttributesW(d.path.c_str(), FILE_ATTRIBUTE_NORMAL); // por si quedó de una ejecución previa
            {
                std::ofstream out(d.path, std::ios::binary | std::ios::trunc);
                if (!out.is_open()) continue;
                out.write(kContent, static_cast<std::streamsize>(sizeof(kContent) - 1));
            }
            SetFileAttributesW(d.path.c_str(), FILE_ATTRIBUTE_HIDDEN);
            d.sha256 = openguard::CryptoUtils::computeSha256(d.path);
            if (!d.sha256.empty()) m_decoys.push_back(std::move(d));
        }
        g_log.write("INFO", "Archivos senuelo anti-ransomware: " + std::to_string(m_decoys.size()));
    }

    void removeDecoys() {
        for (const auto& d : m_decoys) {
            std::error_code ec;
            SetFileAttributesW(d.path.c_str(), FILE_ATTRIBUTE_NORMAL);
            fs::remove(d.path, ec);
        }
        m_decoys.clear();
    }

    void checkDecoys() {
        for (auto& d : m_decoys) {
            if (d.alerted) continue;
            std::error_code ec;
            std::string reason;
            if (!fs::exists(d.path, ec)) {
                reason = "eliminado o renombrado";
            } else if (openguard::CryptoUtils::computeSha256(d.path) != d.sha256) {
                reason = "modificado/cifrado";
            }
            if (!reason.empty()) {
                d.alerted = true;
                hist("ransomware", "ALERT", openguard::paths::toUtf8(d.path), "Senuelo " + reason, "alerta");
                g_log.write("ALERT", "POSIBLE RANSOMWARE: el archivo senuelo " + openguard::paths::toUtf8(d.path) +
                                         " fue " + reason + ". Desconecte el equipo de la red y revise los procesos activos.");
            }
        }
    }

    bool isDecoy(const fs::path& p) const {
        for (const auto& d : m_decoys) if (d.path == p) return true;
        return false;
    }

    /// Cuenta modificaciones recientes en carpetas de usuario: una ráfaga masiva es típica de cifrado.
    void noteActivity(const fs::path& path) {
        const std::wstring lower = [&] {
            std::wstring w = path.wstring();
            for (auto& c : w) c = static_cast<wchar_t>(std::towlower(static_cast<wint_t>(c)));
            return w;
        }();
        if (lower.find(L"\\temp\\") != std::wstring::npos) return; // instaladores y navegadores generan mucho ruido en Temp

        constexpr size_t kBurstThreshold = 150;
        constexpr auto kWindow = std::chrono::seconds(10);
        constexpr auto kAlertCooldown = std::chrono::seconds(60);

        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(m_burstMutex);
        m_recent.push_back(now);
        while (!m_recent.empty() && now - m_recent.front() > kWindow) m_recent.pop_front();

        if (m_recent.size() >= kBurstThreshold && now - m_lastBurstAlert > kAlertCooldown) {
            m_lastBurstAlert = now;
            hist("ransomware", "ALERT", openguard::paths::toUtf8(path), "Rafaga de modificaciones", "alerta",
                 {}, std::to_string(m_recent.size()) + " archivos en 10 s");
            g_log.write("ALERT", "ACTIVIDAD SOSPECHOSA: " + std::to_string(m_recent.size()) +
                                     " archivos modificados en 10 s en carpetas de usuario (posible cifrado masivo). Ultimo: " +
                                     openguard::paths::toUtf8(path));
        }
    }

    std::vector<Decoy> m_decoys;
    std::mutex m_burstMutex;
    std::deque<std::chrono::steady_clock::time_point> m_recent;
    std::chrono::steady_clock::time_point m_lastBurstAlert{};

    void onFileChanged(const fs::path& path) {
        std::error_code ec;
        if (!fs::is_regular_file(path, ec)) return;
        if (isDecoy(path)) return; // El señuelo se vigila aparte (checkDecoys)
        if (isInside(path, openguard::paths::dataDir())) return; // Evita analizar la cuarentena y los logs
        noteActivity(path);
        if (m_set.isExcluded(path)) return; // exclusiones definidas por el usuario
        if (isIgnoredExtension(path)) return;

        openguard::ScanResult result;
        for (int attempt = 0; attempt < 3; ++attempt) {
            result = m_scanner->scanFile(path);
            // El archivo puede seguir bloqueado por quien lo escribe: reintentar brevemente
            if (!(result.skipped && result.error.rfind("Error de lectura", 0) == 0)) break;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        handleResult(result);
    }

    void scanRemovable(const fs::path& root) {
        openguard::FileScanner scanner(m_db, m_config);
        auto session = scanner.scanPath(root, openguard::ScanType::USB);
        for (const auto& r : session.results) {
            if (r.isThreat()) handleResult(r);
        }
        g_log.write("INFO", "Analisis de " + openguard::paths::toUtf8(root) + " completado: " +
                                std::to_string(session.filesScanned) + " archivos, " +
                                std::to_string(session.threatsFound) + " amenazas");
    }

    void handleResult(const openguard::ScanResult& r) {
        if (!r.isThreat()) return;

        const std::string pathStr = openguard::paths::toUtf8(r.filePath);
        std::string names;
        bool confirmed = false;
        for (const auto& t : r.threats) {
            if (!names.empty()) names += ", ";
            names += t.name;
            if (t.method == "hash_signature") confirmed = true;
        }
        g_log.write("ALERT", "Amenaza detectada (" + std::to_string(r.riskScore) + "/100): " + pathStr + " -> " + names);
        hist("detection", "ALERT", pathStr, names, "detectado", r.sha256, "riesgo " + std::to_string(r.riskScore) + "/100");

        // Solo se aísla automáticamente lo confirmado: una heurística puede equivocarse y no debe
        // destruir archivos legítimos del usuario sin su decisión.
        if (m_autoQuarantine && (confirmed || r.riskLevel == openguard::RiskLevel::Critical)) {
            const auto& first = r.threats.front();
            auto item = m_vault->quarantineFile(r.filePath, first.name, first.severity, r.sha256);
            if (item) {
                g_log.write("ACTION", "Archivo aislado en cuarentena (id " + item->qid + "): " + pathStr);
                hist("quarantine", "ACTION", pathStr, first.name, "aislado en cuarentena", r.sha256, "id " + item->qid);
            } else {
                g_log.write("ERROR", "No se pudo aislar el archivo: " + pathStr);
            }
        } else {
            g_log.write("INFO", "Sospechoso no confirmado: se registra sin aislar (revise con 'openguard_cli scan')");
        }
    }

    std::shared_ptr<openguard::SignatureDB> m_db;
    openguard::ScannerConfig m_config;
    std::unique_ptr<openguard::FileScanner> m_scanner;
    std::unique_ptr<openguard::QuarantineVault> m_vault;
    openguard::RealtimeMonitor m_monitor;
    std::set<wchar_t> m_knownRemovable;
    std::vector<std::thread> m_usbThreads;
};

// ---------------------------------------------------------------------------------------------
// Integración con el Service Control Manager
// ---------------------------------------------------------------------------------------------

/**
 * @brief Actualiza el estado del servicio ante el Service Control Manager (SCM).
 */
void reportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;
    if (!g_statusHandle) return; // Modo consola

    g_serviceStatus.dwCurrentState = currentState;
    g_serviceStatus.dwWin32ExitCode = exitCode;
    g_serviceStatus.dwWaitHint = waitHint;

    g_serviceStatus.dwControlsAccepted =
        (currentState == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);

    if ((currentState == SERVICE_RUNNING) || (currentState == SERVICE_STOPPED)) {
        g_serviceStatus.dwCheckPoint = 0;
    } else {
        g_serviceStatus.dwCheckPoint = checkPoint++;
    }

    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

/**
 * @brief Manejador de eventos de control enviados por el SCM (Stop, Shutdown).
 */
DWORD WINAPI serviceCtrlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            reportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
            if (g_stopEvent) SetEvent(g_stopEvent);
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            break;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/**
 * @brief Ciclo de vida del motor: inicia, espera la señal de detención y apaga ordenadamente.
 */
void runEngine() {
    g_log.write("INFO", "OpenGuard Service " OPENGUARD_VERSION " iniciando");

    ProtectionEngine engine;
    const bool ok = engine.start();
    if (!ok) g_log.write("WARN", "El motor arranco con funcionalidad reducida");

    reportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Cada 5 s se revisan las unidades extraíbles; la vigilancia de carpetas corre en sus propios hilos
    while (WaitForSingleObject(g_stopEvent, 5000) == WAIT_TIMEOUT) {
        engine.poll();
    }

    engine.stop();
}

VOID WINAPI serviceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, serviceCtrlHandler, nullptr);
    if (!g_statusHandle) return;

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwServiceSpecificExitCode = 0;

    reportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        reportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    try {
        runEngine();
    } catch (const std::exception& e) {
        g_log.write("ERROR", std::string("Excepcion no controlada: ") + e.what());
    } catch (...) {
        g_log.write("ERROR", "Excepcion desconocida en el servicio");
    }

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    reportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

BOOL WINAPI consoleCtrlHandler(DWORD) {
    if (g_stopEvent) SetEvent(g_stopEvent);
    return TRUE;
}

/**
 * @brief Instala el servicio (inicio automático retardado, reinicio ante fallos) y lo arranca.
 */
bool installService() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        std::wcerr << L"[!] Error: Se requieren privilegios de Administrador para registrar el servicio.\n";
        return false;
    }

    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) {
        CloseServiceHandle(scManager);
        return false;
    }
    // La ruta debe ir entre comillas: evita la vulnerabilidad de "unquoted service path" en Program Files
    const std::wstring quotedPath = L"\"" + std::wstring(path) + L"\"";

    SC_HANDLE service = CreateServiceW(
        scManager, SERVICE_NAME, SERVICE_DISPLAY_NAME, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        quotedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!service) {
        const DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::wcout << L"[+] El servicio OpenGuard ya se encuentra instalado.\n";
            service = OpenServiceW(scManager, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
            if (service) {
                StartServiceW(service, 0, nullptr); // Si ya corre, devuelve error que se ignora
                CloseServiceHandle(service);
            }
            CloseServiceHandle(scManager);
            return true;
        }
        std::wcerr << L"[!] Fallo al crear el servicio. Codigo de error: " << err << L"\n";
        CloseServiceHandle(scManager);
        return false;
    }

    SERVICE_DESCRIPTIONW desc{};
    desc.lpDescription = const_cast<LPWSTR>(SERVICE_DESCRIPTION);
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);

    SERVICE_DELAYED_AUTO_START_INFO delayed{};
    delayed.fDelayedAutostart = TRUE;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

    SC_ACTION actions[3] = {
        { SC_ACTION_RESTART, 5000 },
        { SC_ACTION_RESTART, 15000 },
        { SC_ACTION_RESTART, 60000 },
    };
    SERVICE_FAILURE_ACTIONSW failure{};
    failure.dwResetPeriod = 24 * 60 * 60;
    failure.cActions = 3;
    failure.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);

    std::wcout << L"[+] Servicio OpenGuard instalado con exito.\n";
    if (StartServiceW(service, 0, nullptr)) {
        std::wcout << L"[+] Servicio iniciado.\n";
    } else {
        std::wcerr << L"[!] El servicio se instalo pero no pudo iniciarse (codigo " << GetLastError() << L").\n";
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

/**
 * @brief Detiene (si corre) y elimina el servicio.
 */
bool uninstallService() {
    SC_HANDLE scManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) return false;

    SC_HANDLE service = OpenServiceW(scManager, SERVICE_NAME, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        const DWORD err = GetLastError();
        CloseServiceHandle(scManager);
        return err == ERROR_SERVICE_DOES_NOT_EXIST; // Ya no existe: nada que desinstalar
    }

    SERVICE_STATUS status{};
    if (ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        for (int i = 0; i < 40; ++i) { // Espera hasta 10 s a que termine
            if (!QueryServiceStatus(service, &status) || status.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(250);
        }
    }

    const bool success = DeleteService(service) != 0;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);

    if (success) std::wcout << L"[+] Servicio OpenGuard desinstalado con exito.\n";
    return success;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        const std::wstring arg = argv[1];
        if (arg == L"/install" || arg == L"-install" || arg == L"--install") {
            return installService() ? 0 : 1;
        }
        if (arg == L"/uninstall" || arg == L"-uninstall" || arg == L"--uninstall") {
            return uninstallService() ? 0 : 1;
        }
        if (arg == L"/console" || arg == L"-console" || arg == L"--console") {
            // Ejecución en primer plano para depuración (Ctrl+C para salir)
            g_consoleMode = true;
            g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
            try {
                runEngine();
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << "\n";
                return 1;
            }
            return 0;
        }
    }

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(SERVICE_NAME), serviceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        const DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcout << L"OpenGuard Service - ejecutable del servicio de proteccion en tiempo real\n"
                       << L"  Registrar e iniciar como servicio : " << argv[0] << L" --install\n"
                       << L"  Remover el servicio               : " << argv[0] << L" --uninstall\n"
                       << L"  Ejecutar en primer plano (debug)  : " << argv[0] << L" --console\n";
            return 0;
        }
        return 1;
    }

    return 0;
}
