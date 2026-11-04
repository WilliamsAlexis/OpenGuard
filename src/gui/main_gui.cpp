/**
 * @file main_gui.cpp
 * @brief Interfaz gráfica de OpenGuard (Win32 + GDI, sin dependencias externas).
 * @details Diseño tipo suite antivirus comercial: panel lateral de navegación y páginas de
 *          Inicio (estado de protección), Análisis, Actualización, Cuarentena, Informes y Configuración.
 *          Los análisis y descargas corren en hilos; la UI se actualiza mediante mensajes de ventana.
 */

#include "openguard/paths.h"
#include "openguard/quarantine.h"
#include "openguard/scanner.h"
#include "openguard/signatures.h"
#include "openguard/app_update.h"
#include "openguard/cleaner.h"
#include "openguard/heuristics.h"
#include "openguard/drive_tools.h"
#include "openguard/feeds.h"
#include "openguard/secrets.h"
#include "openguard/history.h"
#include "openguard/isolated_scan.h"
#include "openguard/settings.h"
#include "openguard/updater.h"
#include "openguard/yara_lite.h"

#include <windows.h>
#include <windowsx.h>
#include <ole2.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dbt.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <cctype>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// GDI+: bordes suaves, degradados, transparencias y brillos. Con NOMINMAX, sus cabeceras necesitan min/max de std.
using std::min;
using std::max;
#include <gdiplus.h>
#include <uxtheme.h>

#ifndef OPENGUARD_VERSION
#define OPENGUARD_VERSION "0.4.4"
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "uxtheme.lib")

namespace {

namespace fs = std::filesystem;

// ----------------------------------------------------------------------------- paleta

// Tema oscuro futurista: fondo #0B0F1A, paneles #121826, acentos cian #00E5FF y violeta #7C4DFF
constexpr COLORREF C_BG = RGB(11, 15, 26);
constexpr COLORREF C_CARD = RGB(18, 24, 38);
constexpr COLORREF C_SIDE = RGB(9, 12, 22);
constexpr COLORREF C_SIDE_HOT = RGB(22, 30, 50);
constexpr COLORREF C_ACCENT = RGB(0, 229, 255);
constexpr COLORREF C_ACCENT_HOT = RGB(110, 240, 255);
constexpr COLORREF C_VIOLET = RGB(124, 77, 255);
constexpr COLORREF C_BORDER = RGB(40, 51, 76);
constexpr COLORREF C_TEXT = RGB(232, 237, 247);
constexpr COLORREF C_MUTED = RGB(138, 151, 176);
constexpr COLORREF C_OK = RGB(0, 230, 118);
constexpr COLORREF C_WARN = RGB(255, 179, 0);
constexpr COLORREF C_BAD = RGB(255, 61, 113);
constexpr COLORREF C_WHITE = RGB(255, 255, 255);
constexpr COLORREF C_ON_ACCENT = RGB(4, 14, 26);
constexpr COLORREF C_SIDE_TEXT = RGB(150, 163, 190);

// ----------------------------------------------------------------------------- ids y mensajes

enum Page { PG_HOME, PG_SCAN, PG_THREATS, PG_CLEANER, PG_UPDATE, PG_QUARANTINE, PG_REPORTS, PG_SETTINGS, PG_COUNT, PG_EXCLUSIONS, PG_SCHEDULE, PG_FEEDS }; // PG_EXCLUSIONS y PG_SCHEDULE: subpáginas sin entrada en el menú

enum : int {
    NAV_BASE = 100,                       // NAV_BASE + Page
    NAV_SCAN = NAV_BASE + 1, NAV_THREATS = NAV_BASE + 2, NAV_CLEANER = NAV_BASE + 3, NAV_UPDATE = NAV_BASE + 4, NAV_QUARANTINE = NAV_BASE + 5,  // = NAV_BASE + PG_xxx
    ID_SCAN_QUICK = 200, ID_SCAN_FULL, ID_SCAN_FOLDER, ID_CANCEL, ID_ISOLATE,
    ID_UPDATE_NOW, ID_IMPORT_FILE, ID_Q_RESTORE, ID_Q_DELETE, ID_Q_REFRESH,
    ID_LOG_OPEN, ID_LOG_REFRESH, ID_TOGGLE_PROTECTION, ID_SAVE_SETTINGS, ID_FIX,
    ID_APP_CHECK, ID_APP_INSTALL, ID_APP_PAGE,
    ID_CPU_25, ID_CPU_50, ID_CPU_75, ID_CPU_100,
    ID_EXCL_OPEN, ID_EXCL_ADD_DIR, ID_EXCL_ADD_FILE, ID_EXCL_REMOVE, ID_EXCL_BACK,
    ID_SCHED_OPEN, ID_SCHED_BACK, ID_SCHED_SAVE, ID_SCHED_QUICK, ID_SCHED_FULL, ID_SCHED_DAILY, ID_SCHED_WEEKLY,
    ID_SCHED_HOUR_UP, ID_SCHED_HOUR_DOWN, ID_SCHED_MIN_UP, ID_SCHED_MIN_DOWN, ID_SCHED_DAY_NEXT,
    ID_USB_MODE, ID_THREAT_MODE,
    ID_THREAT_ISOLATE, ID_THREAT_DELETE, ID_THREAT_IGNORE, ID_THREAT_OPEN, ID_THREAT_ALL, ID_CLEAN_ANALYZE, ID_CLEAN_RUN,
    ID_FEEDS_OPEN, ID_FEEDS_BACK, ID_FEEDS_SAVE, ID_FEEDS_RUN, ID_FEED_HOURS, ID_FEED_KEY_PASTE, ID_FEED_KEY_REMOVE,
    TOG_AUTOQ = 300, TOG_DECOY, TOG_USB, TOG_NOTIFY, TOG_APPUPD, TOG_SCHED, TOG_DOWNLOADS, TOG_TRAY, TOG_AUTOSTART, TOG_AUTOUPD, TOG_FEEDRULES, TOG_BAZAAR
};

constexpr UINT WM_APP_PROGRESS = WM_APP + 1;
constexpr UINT WM_APP_DONE = WM_APP + 2;
constexpr UINT WM_APP_TRAY = WM_APP + 3;
constexpr UINT WM_APP_UPDATE_DONE = WM_APP + 4;
constexpr UINT WM_APP_USB = WM_APP + 7;     // se conectó una unidad (wParam = letra)
constexpr UINT WM_APP_SHOW = WM_APP + 8;
constexpr UINT WM_APP_FEEDS_DONE = WM_APP + 9;    // otra instancia pide mostrar la ventana
constexpr UINT WM_APP_CLEAN_DONE = WM_APP + 10;   // termino el analisis o la limpieza de temporales
constexpr int TOG_CLEAN_BASE = 700;                  // TOG_CLEAN_BASE + indice de categoria
enum : int { ID_TRAY_OPEN = 400, ID_TRAY_QUICK, ID_TRAY_TOGGLE, ID_TRAY_EXIT };
enum : int { ID_DRV_ISOLATE = 5001, ID_DRV_REPAIR, ID_DRV_DETAILS, ID_DRV_CLOSE, ID_DRV_SCAN, ID_DRV_LATER };
constexpr UINT WM_APP_APPCHECK_DONE = WM_APP + 5;
constexpr UINT WM_APP_APPDL_DONE = WM_APP + 6;
constexpr UINT_PTR TIMER_REFRESH = 1;
constexpr UINT_PTR TIMER_LOGPOLL = 2;
constexpr UINT_PTR TIMER_ANIM = 4;
constexpr UINT_PTR TIMER_APPCHECK = 3;
constexpr int IDC_LIST = 1001;
constexpr int IDC_PROGRESS = 1002;

enum class Svc { NotInstalled, Stopped, Running, Pending };

struct HitBox { RECT r; int id; };

struct Settings { bool autoQuarantine{true}, decoys{true}, scanUsb{true}, notify{true}, checkAppUpdates{true},
                       scanDownloads{true}, closeToTray{true}, autostart{false}; };

struct DownloadResult { bool ok{false}; std::wstring path; std::wstring error; };

struct Toast { std::wstring text; COLORREF color; ULONGLONG expire; };

struct AppState {
    HWND main{}, list{}, progress{};
    HINSTANCE hInst{};
    double scale{1.0};
    HFONT fH1{}, fH2{}, fBody{}, fSmall{}, fBold{}, fBig{}, fIcon{};
    HICON icon{};

    std::shared_ptr<openguard::SignatureDB> db;
    std::shared_ptr<openguard::FileScanner> scanner;
    std::mutex scannerMutex;
    std::thread worker, updater, appThread;
    std::atomic<bool> scanning{false};
    std::atomic<bool> updating{false};
    std::atomic<bool> appBusy{false};
    openguard::AppUpdateInfo appInfo;
    bool appChecked{false}, appSilentCheck{false};
    std::wstring appMsg;
    std::atomic<size_t> processed{0};

    Page page{PG_HOME};
    int hover{0};
    bool tracking{false};
    std::vector<HitBox> hits;

    Svc svc{Svc::NotInstalled};
    size_t sigCount{0}, yaraCount{0}, quarantineCount{0};
    std::vector<openguard::ScanResult> threats;
    std::vector<openguard::HistoryEvent> pending;       // amenazas detectadas aun sin resolver (del historial)
    // Limpieza de temporales
    struct CleanRow { openguard::cleaner::Category cat; bool selected{true}; bool measured{false}; openguard::cleaner::Usage usage; };
    std::vector<CleanRow> clean;
    std::thread cleanThread;
    std::atomic<bool> cleanBusy{false}, cleanCancel{false};
    std::wstring cleanMsg;
    bool cleanMsgOk{true};
    std::vector<openguard::QuarantineItem> quarantined;
    std::wstring scanStatus, updateMsg;
    bool updateOk{true};
    Settings settings;
    openguard::ProtectionSettings prot;                  // configuración compartida con el servicio
    std::unique_ptr<openguard::ThreatHistory> history;   // historial estructurado
    bool scanTotalKnown{false};
    // Fuentes de firmas
    std::wstring feedMsg;
    bool feedOk{true};
    std::thread feedThread;
    std::atomic<bool> feedBusy{false};
    // Unidades externas
    std::wstring driveRoot;                       // unidad en análisis (vacío si el análisis no es de una unidad)
    openguard::DriveInspection driveInspection;   // síntomas detectados en esa unidad
    std::vector<wchar_t> pendingDrives;           // unidades en espera de que termine el análisis actual
    // Segundo plano
    bool quitting{false};                         // el usuario eligió Salir (no ocultar en la bandeja)
    bool trayHintShown{false};
    HANDLE instanceMutex{nullptr};
    // Configuración con desplazamiento
    // Diseño: GDI+, animación y datos en caché para la pantalla de inicio
    Gdiplus::Graphics* gfx{nullptr};
    ULONG_PTR gdiplusToken{0};
    double animPhase{0};
    RECT animRect{};
    std::vector<Toast> toasts;
    std::vector<openguard::HistoryEvent> feed;
    int chartCounts[7]{};
    size_t threatsBlocked{0}, threatsDetected{0}, totalScanned{0};
    std::wstring lastScanText, lastUpdateText, isoText;
    ULONGLONG homeCacheTick{0};
    int settingsScroll{0}, settingsMaxScroll{0};

    RECT clipRect{};
    bool clipOn{false};                           // el análisis en curso conoce su total (barra determinada)
    std::shared_ptr<openguard::IsolatedScanner> isolated;     // análisis aislado para los análisis manuales
    std::shared_ptr<openguard::FileScanner> isolatedFallback; // respaldo en proceso si el trabajador no puede iniciarse
} g;

int S(int v) { return static_cast<int>(v * g.scale + 0.5); }
RECT R(int l, int t, int r, int b) { RECT rc{l, t, r, b}; return rc; }
std::wstring W(const std::string& utf8) { return openguard::paths::fromUtf8(utf8).wstring(); }

/// Notificación flotante dentro de la ventana (se desvanece sola a los pocos segundos).
void pushToast(const std::wstring& text, COLORREF color, unsigned ms = 4500) {
    if (g.toasts.size() >= 3) g.toasts.erase(g.toasts.begin());
    g.toasts.push_back({text, color, GetTickCount64() + ms});
    if (g.main) InvalidateRect(g.main, nullptr, FALSE);
}


// ----------------------------------------------------------------------------- ajustes (ini)

fs::path serviceIni() { return openguard::paths::dataDir() / L"config.ini"; }

fs::path guiIni() {
    wchar_t buf[MAX_PATH * 2]{};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, static_cast<DWORD>(std::size(buf)));
    fs::path dir = n ? fs::path(std::wstring(buf, n)) / L"OpenGuard" : fs::temp_directory_path();
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir / L"gui.ini";
}

std::wstring iniGetStr(const fs::path& ini, const wchar_t* sec, const wchar_t* key, const wchar_t* def = L"") {
    wchar_t buf[512]{};
    GetPrivateProfileStringW(sec, key, def, buf, static_cast<DWORD>(std::size(buf)), ini.c_str());
    return buf;
}
void iniSetStr(const fs::path& ini, const wchar_t* sec, const wchar_t* key, const std::wstring& v) {
    WritePrivateProfileStringW(sec, key, v.c_str(), ini.c_str());
}
bool iniGetBool(const fs::path& ini, const wchar_t* sec, const wchar_t* key, bool def) {
    return GetPrivateProfileIntW(sec, key, def ? 1 : 0, ini.c_str()) != 0;
}

std::wstring nowText() {
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t buf[32];
    swprintf(buf, std::size(buf), L"%04d-%02d-%02d %02d:%02d", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute);
    return buf;
}

bool isAutostartEnabled(); // definida junto a runAndWait

void loadSettings() {
    g.prot = openguard::ProtectionSettings::load();
    g.settings.autoQuarantine = g.prot.autoQuarantine;
    g.settings.decoys = g.prot.decoys;
    g.settings.scanUsb = g.prot.scanUsb;
    g.settings.scanDownloads = g.prot.scanDownloads;
    g.settings.closeToTray = iniGetBool(guiIni(), L"gui", L"close_to_tray", true);
    g.settings.autostart = isAutostartEnabled();
    g.settings.notify = iniGetBool(guiIni(), L"gui", L"notifications", true);
    g.settings.checkAppUpdates = iniGetBool(guiIni(), L"gui", L"check_app_updates", true);
}

bool saveSettings() {
    g.prot.decoys = g.settings.decoys;
    g.prot.scanDownloads = g.settings.scanDownloads;
    iniSetStr(guiIni(), L"gui", L"close_to_tray", g.settings.closeToTray ? L"1" : L"0");
    iniSetStr(guiIni(), L"gui", L"notifications", g.settings.notify ? L"1" : L"0");
    iniSetStr(guiIni(), L"gui", L"check_app_updates", g.settings.checkAppUpdates ? L"1" : L"0");
    return g.prot.save();
}

// ----------------------------------------------------------------------------- servicio de Windows

Svc queryService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return Svc::NotInstalled;
    Svc result = Svc::NotInstalled;
    if (SC_HANDLE svc = OpenServiceW(scm, L"OpenGuardService", SERVICE_QUERY_STATUS)) {
        SERVICE_STATUS st{};
        result = Svc::Stopped;
        if (QueryServiceStatus(svc, &st)) {
            if (st.dwCurrentState == SERVICE_RUNNING) result = Svc::Running;
            else if (st.dwCurrentState != SERVICE_STOPPED) result = Svc::Pending;
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return result;
}

bool runAndWait(const std::wstring& exe, const std::wstring& args) {
    std::wstring cmd = L"\"" + exe + L"\" " + args;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    WaitForSingleObject(pi.hProcess, 20000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

fs::path systemExe(const wchar_t* name) {
    wchar_t dir[MAX_PATH]{};
    GetSystemDirectoryW(dir, MAX_PATH);
    return fs::path(dir) / name;
}

/// ¿Existe la tarea programada que inicia OpenGuard en segundo plano al iniciar sesión?
bool isAutostartEnabled() {
    return runAndWait(systemExe(L"schtasks.exe").wstring(), L"/Query /TN \"OpenGuard Tray\"");
}

/// Crea o elimina la tarea programada "OpenGuard Tray" (inicio en segundo plano con privilegios elevados, sin
/// pedir confirmación en cada inicio de sesión).
bool setAutostart(bool enable) {
    if (enable) {
        const std::wstring exe = (openguard::paths::executableDir() / L"openguard_gui.exe").wstring();
        return runAndWait(systemExe(L"schtasks.exe").wstring(),
                          L"/Create /TN \"OpenGuard Tray\" /TR \"\\\"" + exe + L"\\\" --tray\" /SC ONLOGON /RL HIGHEST /F");
    }
    return runAndWait(systemExe(L"schtasks.exe").wstring(), L"/Delete /TN \"OpenGuard Tray\" /F");
}

/// Activa o desactiva la protección en tiempo real (instala el servicio si hace falta).
bool setProtection(bool enable, std::wstring& error) {
    const Svc state = queryService();
    if (enable && state == Svc::NotInstalled) {
        const fs::path exe = openguard::paths::executableDir() / L"openguard_service.exe";
        if (!runAndWait(exe.wstring(), L"--install")) { error = L"No se pudo instalar el servicio."; return false; }
        return true;
    }

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { error = L"No se pudo abrir el Administrador de servicios."; return false; }
    SC_HANDLE svc = OpenServiceW(scm, L"OpenGuardService", SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); error = L"El servicio no esta instalado."; return false; }

    bool ok = false;
    if (enable) {
        ok = StartServiceW(svc, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    } else {
        SERVICE_STATUS st{};
        ok = ControlService(svc, SERVICE_CONTROL_STOP, &st) || GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
        for (int i = 0; ok && i < 40; ++i) {
            if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(250);
        }
    }
    if (!ok) error = L"Windows rechazo la operacion (codigo " + std::to_wstring(GetLastError()) + L").";
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

// ----------------------------------------------------------------------------- datos

void refreshData() {
    g.svc = queryService();
    g.sigCount = g.db ? g.db->getStats().totalSignatures : 0;
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        g.quarantineCount = vault.getItemCount();
    } catch (...) {
    }
}

void loadYaraCount() {
    openguard::YaraLite y;
    y.loadDirectories(openguard::paths::signaturesDir() / "yara_rules", openguard::paths::rulesUpdateDir());
    g.yaraCount = y.ruleCount();
}

openguard::ScannerConfig makeConfig() {
    openguard::ScannerConfig cfg;
    cfg.excludedPaths = { openguard::paths::dataDir(), openguard::paths::executableDir(), openguard::paths::signaturesDir() };
    for (const auto& ex : g.prot.exclusions) cfg.excludedPaths.push_back(ex);
    cfg.threadCount = g.prot.threadCount();   // límite de CPU elegido por el usuario
    cfg.yaraRulesDir = openguard::paths::signaturesDir() / "yara_rules";
    cfg.yaraUpdatesDir = openguard::paths::rulesUpdateDir();

    // La GUI corre elevada: analizar archivos hostiles en su propio proceso sería peor que en el servicio.
    // Los análisis manuales usan también el proceso trabajador aislado (con respaldo en proceso).
    if (g.prot.isolatedScan) {
        if (!g.isolated) {
            openguard::IsolatedScanner::Options opts;
            opts.workerExe = openguard::paths::executableDir() / "openguard_worker.exe";
            g.isolated = std::make_shared<openguard::IsolatedScanner>(g.db, opts);
        }
        if (g.isolated->available()) {
            if (!g.isolatedFallback) {
                openguard::ScannerConfig fb = cfg;
                fb.threadCount = 1;
                g.isolatedFallback = std::make_shared<openguard::FileScanner>(g.db, fb);
            }
            auto iso = g.isolated;
            auto fallback = g.isolatedFallback;
            cfg.customAnalyzer = [iso, fallback](const fs::path& p) -> openguard::ScanResult {
                if (auto r = iso->scan(p)) return *r;
                return fallback->scanFile(p);
            };
        }
    }
    return cfg;
}

// Declaraciones adelantadas: se definen más abajo en este archivo
void showBalloon(const std::wstring& title, const std::wstring& body, DWORD icon);
void startScan(std::vector<fs::path> targets, openguard::ScanType type);
void showPage(Page p);
void fillThreatList();

/// Muestra la ventana principal (desde la bandeja, otra instancia o un aviso).
void showMainWindow() {
    ShowWindow(g.main, IsIconic(g.main) ? SW_RESTORE : SW_SHOWNORMAL);
    SetForegroundWindow(g.main);
}

// ----------------------------------------------------------------------------- unidades externas

int showTaskDialog(const std::wstring& title, const std::wstring& instruction, const std::wstring& content,
                   const std::wstring& expanded, const std::vector<std::pair<int, std::wstring>>& buttons,
                   PCWSTR icon, bool commandLinks) {
    std::vector<TASKDIALOG_BUTTON> tdButtons;
    for (const auto& b : buttons) tdButtons.push_back({b.first, b.second.c_str()});

    TASKDIALOGCONFIG cfg{};
    cfg.cbSize = sizeof(cfg);
    cfg.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_EXPAND_FOOTER_AREA | (commandLinks ? TDF_USE_COMMAND_LINKS : 0);
    cfg.pszWindowTitle = title.c_str();
    cfg.pszMainInstruction = instruction.c_str();
    cfg.pszContent = content.c_str();
    if (!expanded.empty()) {
        cfg.pszExpandedInformation = expanded.c_str();
        cfg.pszCollapsedControlText = L"Ver medidas recomendadas";
        cfg.pszExpandedControlText = L"Ocultar medidas recomendadas";
    }
    cfg.pButtons = tdButtons.data();
    cfg.cButtons = static_cast<UINT>(tdButtons.size());
    cfg.nDefaultButton = tdButtons.empty() ? 0 : tdButtons[0].nButtonID;
    cfg.pszMainIcon = icon;
    cfg.pfCallback = [](HWND hwnd, UINT msg, WPARAM, LPARAM, LONG_PTR) -> HRESULT {
        if (msg == TDN_CREATED) { // aparece al frente aunque OpenGuard esté oculto en la bandeja
            SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            SetForegroundWindow(hwnd);
        }
        return S_OK;
    };

    int pressed = 0;
    if (FAILED(TaskDialogIndirect(&cfg, &pressed, nullptr, nullptr))) return 0;
    return pressed;
}

const wchar_t* kDriveMeasures =
    L"\x2022 No abra ni ejecute archivos de la unidad hasta limpiarla.\n"
    L"\x2022 Aisle las amenazas en cuarentena con el boton correspondiente.\n"
    L"\x2022 Use \"Reparar la unidad\" para mostrar archivos ocultos y quitar accesos directos y autorun maliciosos.\n"
    L"\x2022 Desactive la reproduccion automatica de unidades externas en Configuracion de Windows.\n"
    L"\x2022 Si las amenazas reaparecen, copie sus documentos a un lugar seguro y formatee la unidad.\n"
    L"\x2022 Ejecute tambien un analisis completo del equipo.";

/// Archivos dentro de la carpeta de Windows: aislarlos o borrarlos puede dejar el sistema sin arrancar.
bool isProtectedSystemPath(const fs::path& p) {
    wchar_t win[MAX_PATH]{};
    if (!GetWindowsDirectoryW(win, MAX_PATH)) return false;
    std::wstring a = p.lexically_normal().wstring();
    std::wstring b = fs::path(win).lexically_normal().wstring();
    for (auto& c : a) c = static_cast<wchar_t>(towlower(c));
    for (auto& c : b) c = static_cast<wchar_t>(towlower(c));
    if (!b.empty() && b.back() != L'\\') b += L'\\';
    return a.rfind(b, 0) == 0;
}

void isolateAllThreats(int& ok, int& fail, const char* reason = "unidad externa") {
    ok = 0;
    fail = 0;
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        for (auto it = g.threats.begin(); it != g.threats.end();) {
            const auto& first = it->threats.front();
            if (isProtectedSystemPath(it->filePath)) { ++fail; ++it; continue; }
            if (vault.quarantineFile(it->filePath, first.name, first.severity, it->sha256)) {
                ++ok;
                if (g.history) {
                    openguard::HistoryEvent e;
                    e.kind = "quarantine";
                    e.level = "ACTION";
                    e.path = openguard::paths::toUtf8(it->filePath);
                    e.threat = first.name;
                    e.action = std::string("aislado en cuarentena (") + reason + ")";
                    e.sha256 = it->sha256;
                    g.history->record(e);
                }
                it = g.threats.erase(it);
            } else {
                ++fail;
                ++it;
            }
        }
    } catch (...) {
        fail = static_cast<int>(g.threats.size());
    }
}

/// Resultado del análisis de una unidad: amenazas, síntomas de infección y medidas recomendadas, con acciones.
void finishDriveScan() {
    const std::wstring root = g.driveRoot;
    g.driveRoot.clear();
    g.driveInspection = openguard::inspectDrive(fs::path(root)); // actualizado tras el análisis

    for (;;) {
        const size_t n = g.threats.size();
        const bool issues = g.driveInspection.needsRepair();

        if (n == 0 && !issues) {
            showBalloon(L"Unidad " + root.substr(0, 2), L"No se encontraron amenazas ni sintomas de infeccion.", NIIF_INFO);
            return;
        }

        std::wstring instruction = n > 0 ? L"Se encontraron " + std::to_wstring(n) + L" amenazas en la unidad " + root.substr(0, 2)
                                         : L"La unidad " + root.substr(0, 2) + L" presenta sintomas de infeccion";
        std::wstring content;
        size_t shown = 0;
        for (const auto& r : g.threats) {
            if (shown++ >= 5) { content += L"...y " + std::to_wstring(n - 5) + L" mas.\n"; break; }
            content += r.filePath.filename().wstring() + L"  ->  " + (r.threats.empty() ? L"" : W(r.threats.front().name)) + L"\n";
        }
        if (issues) {
            content += L"\nSintomas en la unidad:\n";
            size_t k = 0;
            for (const auto& f : g.driveInspection.findings) {
                if (k++ >= 4) { content += L"...y otros.\n"; break; }
                content += L"\x2022 " + W(f.description) + L"\n";
            }
        }
        content += L"\nNo abra los archivos de la unidad mientras tanto.";

        std::vector<std::pair<int, std::wstring>> buttons;
        if (n > 0) buttons.push_back({ID_DRV_ISOLATE, L"Aislar las amenazas en cuarentena\nLos archivos infectados se cifran y se sacan de la unidad."});
        if (issues) buttons.push_back({ID_DRV_REPAIR, L"Reparar la unidad\nMuestra los archivos ocultos y elimina accesos directos y autorun maliciosos."});
        buttons.push_back({ID_DRV_DETAILS, L"Ver detalles en OpenGuard"});
        buttons.push_back({ID_DRV_CLOSE, L"Cerrar"});

        const int choice = showTaskDialog(L"OpenGuard - Unidad externa", instruction, content, kDriveMeasures, buttons,
                                          n > 0 ? TD_ERROR_ICON : TD_WARNING_ICON, true);

        if (choice == ID_DRV_ISOLATE) {
            int ok = 0, fail = 0;
            isolateAllThreats(ok, fail);
            fillThreatList();
            refreshData();
            InvalidateRect(g.main, nullptr, FALSE);
            if (fail > 0) {
                MessageBoxW(nullptr, (std::to_wstring(ok) + L" aislados, " + std::to_wstring(fail) +
                                      L" con error (archivos en uso o sin permisos).").c_str(), L"OpenGuard", MB_OK | MB_ICONWARNING | MB_TOPMOST);
            }
            continue; // se vuelve a mostrar el estado actualizado
        }
        if (choice == ID_DRV_REPAIR) {
            const auto res = openguard::repairDrive(g.driveInspection);
            if (g.history) {
                openguard::HistoryEvent e;
                e.kind = "usb_repair";
                e.level = "ACTION";
                e.path = openguard::paths::toUtf8(fs::path(root));
                e.threat = "Reparacion de unidad";
                e.action = "reparada";
                e.details = std::to_string(res.unhidden) + " visibles, " + std::to_string(res.removedShortcuts) + " accesos directos y " +
                            std::to_string(res.removedAutorun) + " autorun eliminados, " + std::to_string(res.failed) + " con error";
                g.history->record(e);
            }
            std::wstring msg = L"Archivos mostrados: " + std::to_wstring(res.unhidden) + L"\nAccesos directos eliminados: " +
                               std::to_wstring(res.removedShortcuts) + L"\nAutorun eliminados: " + std::to_wstring(res.removedAutorun);
            if (res.failed) msg += L"\nNo se pudieron corregir: " + std::to_wstring(res.failed);
            MessageBoxW(nullptr, msg.c_str(), L"Unidad reparada", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
            g.driveInspection = openguard::inspectDrive(fs::path(root));
            continue;
        }
        if (choice == ID_DRV_DETAILS) {
            showMainWindow();
            showPage(PG_SCAN);
        }
        return;
    }
}

void startNextPendingDrive();

/// Lanza el análisis de una unidad y deja anotado que, al terminar, hay que mostrar su resultado.
void analyzeDrive(wchar_t letter) {
    const std::wstring root = std::wstring{letter, L':', L'\\'};
    if (g.scanning) {
        g.pendingDrives.push_back(letter);
        showBalloon(L"Unidad " + root.substr(0, 2), L"Se analizara al terminar el analisis en curso.", NIIF_INFO);
        return;
    }
    g.driveRoot = root;
    g.driveInspection = openguard::inspectDrive(fs::path(root));
    startScan({fs::path(root)}, openguard::ScanType::USB);
}

void startNextPendingDrive() {
    if (g.scanning || g.pendingDrives.empty()) return;
    const wchar_t letter = g.pendingDrives.front();
    g.pendingDrives.erase(g.pendingDrives.begin());
    analyzeDrive(letter);
}

/// Se conectó un volumen: en modo "preguntar" se pide permiso para analizarlo.
void onVolumeArrived(wchar_t letter) {
    if (g.prot.usbMode != "ask") return; // "auto": lo hace el servicio; "off": no se analiza

    static std::map<wchar_t, std::chrono::steady_clock::time_point> lastPrompt;
    const auto now = std::chrono::steady_clock::now();
    auto it = lastPrompt.find(letter);
    if (it != lastPrompt.end() && now - it->second < std::chrono::seconds(10)) return; // el mismo evento llega varias veces
    lastPrompt[letter] = now;

    const std::wstring root = std::wstring{letter, L':', L'\\'};
    const UINT type = GetDriveTypeW(root.c_str());
    if (type != DRIVE_REMOVABLE && type != DRIVE_CDROM && type != DRIVE_FIXED) return; // se ignoran red y RAM

    wchar_t label[MAX_PATH + 1]{};
    GetVolumeInformationW(root.c_str(), label, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0);
    const std::wstring name = label[0] ? std::wstring(label) : std::wstring(L"Unidad sin nombre");
    const wchar_t* kind = type == DRIVE_CDROM ? L"disco optico" : type == DRIVE_REMOVABLE ? L"unidad extraible" : L"disco externo";

    const std::wstring instruction = L"Se conecto " + std::wstring(kind) + L" " + root.substr(0, 2) + L" (" + name + L")";
    const std::wstring content = L"Las unidades externas pueden contener virus: autorun, accesos directos falsos, archivos ocultos o programas "
                                 L"maliciosos. ¿Permite que OpenGuard analice su contenido ahora?\n\nLos archivos solo se leen; nunca se ejecutan.";
    const int choice = showTaskDialog(L"OpenGuard - Unidad externa", instruction, content, L"",
                                      {{ID_DRV_SCAN, L"Analizar ahora (recomendado)"}, {ID_DRV_LATER, L"Ahora no"}},
                                      TD_INFORMATION_ICON, true);
    if (choice == ID_DRV_SCAN) analyzeDrive(letter);
}

std::vector<fs::path> quickTargets() {
    auto env = [](const wchar_t* name) {
        wchar_t buf[MAX_PATH * 2]{};
        DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
        return n ? fs::path(std::wstring(buf, n)) : fs::path();
    };
    std::vector<fs::path> t;
    if (auto p = env(L"USERPROFILE"); !p.empty()) { t.push_back(p / L"Downloads"); t.push_back(p / L"Desktop"); t.push_back(p / L"Documents"); }
    if (auto p = env(L"TEMP"); !p.empty()) t.push_back(p);
    if (auto p = env(L"APPDATA"); !p.empty()) t.push_back(p / L"Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    return t;
}

// ----------------------------------------------------------------------------- dibujo básico
// Las formas se dibujan con GDI+ (suavizado, degradados, transparencia); el texto con GDI (ClearType).

Gdiplus::Color gc(COLORREF c, BYTE alpha = 255) { return Gdiplus::Color(alpha, GetRValue(c), GetGValue(c), GetBValue(c)); }

/// Mezcla dos colores (t = 0..1) para estados "hover".
COLORREF mix(COLORREF a, COLORREF b, double t) {
    return RGB(static_cast<int>(GetRValue(a) + (GetRValue(b) - GetRValue(a)) * t),
               static_cast<int>(GetGValue(a) + (GetGValue(b) - GetGValue(a)) * t),
               static_cast<int>(GetBValue(a) + (GetBValue(b) - GetBValue(a)) * t));
}

/// Sincroniza GDI+ antes de usar GDI sobre el mismo HDC (evita problemas de orden de dibujo).
void flushGdi() { if (g.gfx) g.gfx->Flush(Gdiplus::FlushIntentionSync); }

void addRoundPath(Gdiplus::GraphicsPath& path, RECT rc, int radius) {
    const float w = static_cast<float>(rc.right - rc.left);
    const float h = static_cast<float>(rc.bottom - rc.top);
    const float d = std::min(static_cast<float>(radius) * 2.0f, std::min(w, h));
    const float x = static_cast<float>(rc.left), y = static_cast<float>(rc.top);
    if (d <= 1.0f) { path.AddRectangle(Gdiplus::RectF(x, y, w, h)); return; }
    path.AddArc(x, y, d, d, 180.0f, 90.0f);
    path.AddArc(x + w - d, y, d, d, 270.0f, 90.0f);
    path.AddArc(x + w - d, y + h - d, d, d, 0.0f, 90.0f);
    path.AddArc(x, y + h - d, d, d, 90.0f, 90.0f);
    path.CloseFigure();
}

void fillRect(HDC hdc, RECT rc, COLORREF c) {
    flushGdi();
    HBRUSH b = CreateSolidBrush(c);
    FillRect(hdc, &rc, b);
    DeleteObject(b);
}

void roundRect(HDC, RECT rc, int radius, COLORREF fill, COLORREF border, bool hasBorder) {
    if (!g.gfx) return;
    Gdiplus::GraphicsPath p;
    addRoundPath(p, rc, radius);
    Gdiplus::SolidBrush b(gc(fill));
    g.gfx->FillPath(&b, &p);
    if (hasBorder) {
        Gdiplus::Pen pen(gc(border), 1.0f);
        g.gfx->DrawPath(&pen, &p);
    }
}

/// Resplandor suave alrededor de un rectángulo redondeado (varias capas translúcidas).
void glowRound(RECT rc, int radius, COLORREF color, int layers, BYTE maxAlpha) {
    if (!g.gfx) return;
    for (int i = layers; i >= 1; --i) {
        RECT e = R(rc.left - S(2) * i, rc.top - S(2) * i, rc.right + S(2) * i, rc.bottom + S(2) * i);
        Gdiplus::GraphicsPath p;
        addRoundPath(p, e, radius + S(2) * i);
        const BYTE a = static_cast<BYTE>(maxAlpha * (layers - i + 1) / (layers + 1) / 2);
        Gdiplus::Pen pen(gc(color, a), static_cast<float>(S(2)));
        g.gfx->DrawPath(&pen, &p);
    }
}

/// Panel de cristal: degradado vertical sutil, borde fino semitransparente y brillo superior.
void glassPanel(RECT rc, int radius, COLORREF border = C_BORDER, BYTE borderAlpha = 255) {
    if (!g.gfx) return;
    Gdiplus::GraphicsPath p;
    addRoundPath(p, rc, radius);
    Gdiplus::LinearGradientBrush br(Gdiplus::PointF(0.0f, static_cast<float>(rc.top)),
                                    Gdiplus::PointF(0.0f, static_cast<float>(rc.bottom)),
                                    gc(RGB(26, 35, 56)), gc(C_CARD));
    g.gfx->FillPath(&br, &p);
    Gdiplus::Pen pen(gc(border, borderAlpha), 1.0f);
    g.gfx->DrawPath(&pen, &p);
    Gdiplus::Pen hi(gc(C_WHITE, 22), 1.0f);
    g.gfx->DrawLine(&hi, static_cast<int>(rc.left + radius), static_cast<int>(rc.top + 1), static_cast<int>(rc.right - radius), static_cast<int>(rc.top + 1));
}

void text(HDC hdc, const std::wstring& s, RECT rc, HFONT f, COLORREF c,
          UINT fmt = DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX) {
    flushGdi();
    HGDIOBJ old = SelectObject(hdc, f);
    SetTextColor(hdc, c);
    DrawTextW(hdc, s.c_str(), -1, &rc, fmt);
    SelectObject(hdc, old);
}

void addHit(RECT rc, int id) {
    if (g.clipOn) { // contenido desplazable: la parte fuera de la vista no debe ser pulsable
        RECT inter;
        if (!IntersectRect(&inter, &rc, &g.clipRect)) return;
        rc = inter;
    }
    g.hits.push_back({rc, id});
}

bool isHot(int id) { return g.hover == id; }

/// Recorte común a GDI y GDI+ (contenido desplazable). Devuelve el estado para restaurarlo con endClip().
struct ClipState { int dc{0}; Gdiplus::GraphicsState gs{0}; };
ClipState beginClip(HDC hdc, RECT rc) {
    ClipState st;
    flushGdi();
    st.dc = SaveDC(hdc);
    IntersectClipRect(hdc, rc.left, rc.top, rc.right, rc.bottom);
    if (g.gfx) {
        st.gs = g.gfx->Save();
        g.gfx->SetClip(Gdiplus::Rect(rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top), Gdiplus::CombineModeIntersect);
    }
    return st;
}
void endClip(HDC hdc, const ClipState& st) {
    flushGdi();
    if (g.gfx) g.gfx->Restore(st.gs);
    RestoreDC(hdc, st.dc);
}

/// Escudo con degradado, brillo y marca de verificación.
void drawShield(HDC, int cx, int cy, int size, COLORREF fill, COLORREF check) {
    if (!g.gfx) return;
    static const double pts[8][2] = {{0, -1}, {0.85, -0.72}, {0.85, 0.1}, {0.6, 0.6}, {0, 1}, {-0.6, 0.6}, {-0.85, 0.1}, {-0.85, -0.72}};
    Gdiplus::PointF p[8];
    for (int i = 0; i < 8; ++i) {
        p[i] = Gdiplus::PointF(static_cast<float>(cx + pts[i][0] * size / 2), static_cast<float>(cy + pts[i][1] * size / 2));
    }
    Gdiplus::GraphicsPath path;
    path.AddCurve(p, 8, 0.18f);
    path.CloseFigure();

    for (int i = 3; i >= 1; --i) { // resplandor
        Gdiplus::Pen glow(gc(fill, static_cast<BYTE>(30 / i)), static_cast<float>(S(3) * i));
        g.gfx->DrawPath(&glow, &path);
    }
    Gdiplus::LinearGradientBrush br(Gdiplus::PointF(0.0f, static_cast<float>(cy - size / 2)),
                                    Gdiplus::PointF(0.0f, static_cast<float>(cy + size / 2)),
                                    gc(mix(fill, C_WHITE, 0.35)), gc(mix(fill, C_BG, 0.25)));
    g.gfx->FillPath(&br, &path);

    Gdiplus::Pen chk(gc(check), static_cast<float>(std::max(2, size / 9)));
    chk.SetLineCap(Gdiplus::LineCapRound, Gdiplus::LineCapRound, Gdiplus::DashCapRound);
    chk.SetLineJoin(Gdiplus::LineJoinRound);
    const Gdiplus::PointF c[3] = {Gdiplus::PointF(static_cast<float>(cx - size * 0.22), static_cast<float>(cy + size * 0.02)),
                                  Gdiplus::PointF(static_cast<float>(cx - size * 0.06), static_cast<float>(cy + size * 0.20)),
                                  Gdiplus::PointF(static_cast<float>(cx + size * 0.26), static_cast<float>(cy - size * 0.16))};
    g.gfx->DrawLines(&chk, c, 3);
}

/// Anillo de estado animado: pulso expansivo, aro y arco brillante giratorio con el escudo al centro.
void drawStatusRing(HDC hdc, int cx, int cy, int radius, COLORREF color, double phase) {
    if (!g.gfx) return;
    // Pulsos que se expanden y se desvanecen
    for (int k = 0; k < 3; ++k) {
        const double t = std::fmod(phase * 1.2 + k / 3.0, 1.0);
        const float r = static_cast<float>(radius + t * S(30));
        Gdiplus::Pen pulse(gc(color, static_cast<BYTE>((1.0 - t) * 70)), static_cast<float>(S(2)));
        g.gfx->DrawEllipse(&pulse, cx - r, cy - r, r * 2, r * 2);
    }
    // Disco interior tenue
    Gdiplus::SolidBrush disc(gc(color, 26));
    g.gfx->FillEllipse(&disc, cx - radius + S(8), cy - radius + S(8), (radius - S(8)) * 2, (radius - S(8)) * 2);

    // Aro base y arco brillante que gira
    const float pw = static_cast<float>(S(9));
    Gdiplus::Pen base(gc(color, 70), pw);
    g.gfx->DrawEllipse(&base, cx - radius, cy - radius, radius * 2, radius * 2);

    Gdiplus::LinearGradientBrush grad(Gdiplus::PointF(static_cast<float>(cx - radius), static_cast<float>(cy)),
                                      Gdiplus::PointF(static_cast<float>(cx + radius), static_cast<float>(cy)),
                                      gc(mix(color, C_WHITE, 0.4)), gc(C_VIOLET));
    Gdiplus::Pen arc(&grad, pw);
    arc.SetStartCap(Gdiplus::LineCapRound);
    arc.SetEndCap(Gdiplus::LineCapRound);
    g.gfx->DrawArc(&arc, cx - radius, cy - radius, radius * 2, radius * 2, static_cast<float>(phase * 360.0), 110.0f);

    drawShield(hdc, cx, cy, static_cast<int>(radius * 1.15), color, C_BG);
}

enum BtnStyle { BS_PRIMARY, BS_SECONDARY, BS_DANGER, BS_ONBANNER };

void drawButton(HDC hdc, RECT rc, const std::wstring& label, int id, BtnStyle style, bool enabled = true,
                COLORREF bannerColor = C_ACCENT) {
    (void)bannerColor;
    const bool hot = enabled && isHot(id);
    const int radius = S(10);
    COLORREF fg = C_TEXT;

    if (!enabled) {
        roundRect(hdc, rc, radius, RGB(28, 36, 56), C_BORDER, true);
        fg = RGB(94, 106, 130);
    } else if (style == BS_PRIMARY || style == BS_DANGER) {
        const COLORREF a = style == BS_PRIMARY ? C_ACCENT : C_BAD;
        const COLORREF b = style == BS_PRIMARY ? C_VIOLET : RGB(255, 112, 67);
        if (hot) glowRound(rc, radius, a, 4, 120);
        Gdiplus::GraphicsPath p;
        addRoundPath(p, rc, radius);
        Gdiplus::LinearGradientBrush br(Gdiplus::PointF(static_cast<float>(rc.left), 0.0f),
                                        Gdiplus::PointF(static_cast<float>(rc.right), 0.0f),
                                        gc(hot ? mix(a, C_WHITE, 0.25) : a), gc(hot ? mix(b, C_WHITE, 0.2) : b));
        g.gfx->FillPath(&br, &p);
        fg = style == BS_PRIMARY ? C_ON_ACCENT : C_WHITE;
    } else if (style == BS_ONBANNER) {
        roundRect(hdc, rc, radius, mix(C_CARD, C_WHITE, hot ? 0.25 : 0.12), C_BORDER, true);
    } else { // SECONDARY: cristal con borde que se ilumina
        if (hot) glowRound(rc, radius, C_ACCENT, 3, 90);
        glassPanel(rc, radius, hot ? C_ACCENT : C_BORDER, 255);
    }
    text(hdc, label, rc, g.fBold, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    if (enabled) addHit(rc, id);
}

void drawCard(HDC, RECT rc) { glassPanel(rc, S(16)); }

void drawCardButton(HDC hdc, RECT rc, const std::wstring& title, const std::wstring& desc, int id, bool enabled = true) {
    const bool hot = enabled && isHot(id);
    if (hot) glowRound(rc, S(16), C_ACCENT, 3, 80);
    glassPanel(rc, S(16), hot ? C_ACCENT : C_BORDER, 255);
    RECT t = R(rc.left + S(18), rc.top + S(16), rc.right - S(18), rc.top + S(44));
    text(hdc, title, t, g.fH2, enabled ? C_TEXT : C_MUTED, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    RECT d = R(rc.left + S(18), rc.top + S(48), rc.right - S(18), rc.bottom - S(12));
    text(hdc, desc, d, g.fSmall, C_MUTED);
    if (enabled) addHit(rc, id);
}

void drawToggle(HDC, int x, int y, bool on, int id) {
    if (!g.gfx) return;
    RECT rc = R(x, y, x + S(46), y + S(24));
    Gdiplus::GraphicsPath p;
    addRoundPath(p, rc, S(12));
    if (on) {
        glowRound(rc, S(12), C_ACCENT, 2, 70);
        Gdiplus::LinearGradientBrush br(Gdiplus::PointF(static_cast<float>(rc.left), 0.0f),
                                        Gdiplus::PointF(static_cast<float>(rc.right), 0.0f), gc(C_ACCENT), gc(C_VIOLET));
        g.gfx->FillPath(&br, &p);
    } else {
        Gdiplus::SolidBrush off(gc(RGB(46, 57, 82)));
        g.gfx->FillPath(&off, &p);
        Gdiplus::Pen outline(gc(C_BORDER), 1.0f);
        g.gfx->DrawPath(&outline, &p);
    }
    const int knob = S(18);
    const int kx = on ? rc.right - knob - S(3) : rc.left + S(3);
    Gdiplus::SolidBrush shadow(gc(RGB(0, 0, 0), 60));
    g.gfx->FillEllipse(&shadow, kx, rc.top + S(4), knob, knob);
    Gdiplus::SolidBrush kb(gc(C_WHITE));
    g.gfx->FillEllipse(&kb, kx, rc.top + S(3), knob, knob);
    addHit(R(x - S(4), y - S(4), x + S(50), y + S(28)), id);
}

// ----------------------------------------------------------------------------- lista

void setColumns(const std::vector<std::pair<const wchar_t*, int>>& cols) {
    HWND header = ListView_GetHeader(g.list);
    for (int i = Header_GetItemCount(header) - 1; i >= 0; --i) ListView_DeleteColumn(g.list, i);
    int idx = 0;
    for (const auto& c : cols) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<LPWSTR>(c.first);
        col.cx = S(c.second);
        ListView_InsertColumn(g.list, idx++, &col);
    }
}

void addRow(int row, const std::vector<std::wstring>& cells) {
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    ListView_InsertItem(g.list, &item);
    for (size_t i = 1; i < cells.size(); ++i) {
        ListView_SetItemText(g.list, row, static_cast<int>(i), const_cast<LPWSTR>(cells[i].c_str()));
    }
}

std::vector<int> selectedRows() {
    std::vector<int> rows;
    int i = -1;
    while ((i = ListView_GetNextItem(g.list, i, LVNI_SELECTED)) != -1) rows.push_back(i);
    return rows;
}

const wchar_t* riskName(openguard::RiskLevel r) {
    switch (r) {
        case openguard::RiskLevel::Critical: return L"Critico";
        case openguard::RiskLevel::High:     return L"Alto";
        case openguard::RiskLevel::Medium:   return L"Medio";
        case openguard::RiskLevel::Low:      return L"Bajo";
        default:                             return L"Limpio";
    }
}

void fillThreatList() {
    ListView_DeleteAllItems(g.list);
    setColumns({{L"Archivo", 430}, {L"Amenaza", 250}, {L"Riesgo", 90}});
    int row = 0;
    for (const auto& r : g.threats) {
        std::wstring names;
        for (const auto& t : r.threats) { if (!names.empty()) names += L", "; names += W(t.name); }
        addRow(row++, {r.filePath.wstring(), names, std::wstring(riskName(r.riskLevel)) + L" (" + std::to_wstring(r.riskScore) + L")"});
    }
}

/// Amenazas detectadas (historial) cuyo archivo sigue en su sitio y no esta excluido: lo que falta resolver.
void loadPendingThreats() {
    g.pending.clear();
    if (!g.history) return;
    std::set<std::wstring> seen;
    for (const auto& e : g.history->recent(3000, "detection")) {
        if (e.path.empty()) continue;
        const fs::path p = openguard::paths::fromUtf8(e.path);
        std::wstring key = p.lexically_normal().wstring();
        for (auto& c : key) c = static_cast<wchar_t>(towlower(c));
        if (!seen.insert(key).second) continue; // solo la deteccion mas reciente de cada archivo
        std::error_code ec;
        if (!fs::is_regular_file(p, ec)) continue; // ya aislado, eliminado o movido
        if (g.prot.isExcluded(p)) continue;
        int weak = 0; // detecciones antiguas dentro de librerias (node_modules...) ya no se consideran amenazas
        if (openguard::HeuristicsEngine::weighContentMatch(p, "yara", "high", 70, weak) < 0) continue;
        g.pending.push_back(e);
    }
}

void fillPendingList() {
    ListView_DeleteAllItems(g.list);
    setColumns({{L"Archivo", 430}, {L"Amenaza", 250}, {L"Riesgo", 100}, {L"Detectada", 150}});
    int row = 0;
    for (const auto& e : g.pending) {
        std::wstring risk = W(e.details);
        if (risk.rfind(L"riesgo ", 0) == 0) risk.erase(0, 7);
        addRow(row++, {W(e.path), W(e.threat), risk, W(e.timestamp)});
    }
}

void fillQuarantineList() {
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        g.quarantined = vault.listItems();
    } catch (...) {
        g.quarantined.clear();
    }
    g.quarantineCount = g.quarantined.size();
    ListView_DeleteAllItems(g.list);
    setColumns({{L"Ruta original", 400}, {L"Amenaza", 230}, {L"Fecha", 170}});
    int row = 0;
    for (const auto& q : g.quarantined) addRow(row++, {q.originalPath.wstring(), W(q.threatName), W(q.quarantinedAt)});
}

void fillReportList() {
    ListView_DeleteAllItems(g.list);

    // 1) Historial estructurado (detecciones, cuarentena, ransomware)
    const auto events = g.history ? g.history->recent(500) : std::vector<openguard::HistoryEvent>{};
    if (!events.empty()) {
        setColumns({{L"Fecha", 150}, {L"Tipo", 90}, {L"Amenaza / evento", 230}, {L"Accion", 170}, {L"Ruta", 420}});
        int row = 0;
        for (const auto& e : events) {
            addRow(row++, {W(e.timestamp), W(e.kind), W(e.threat), W(e.action), W(e.path)});
        }
        return;
    }

    // 2) Sin historial todavía: se muestra el registro de texto del servicio
    setColumns({{L"Fecha", 160}, {L"Tipo", 80}, {L"Evento", 600}});
    const fs::path log = openguard::paths::logsDir() / "service.log";
    std::ifstream in(log, std::ios::binary);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        if (lines.size() > 500) lines.erase(lines.begin());
    }
    int row = 0;
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) { // más recientes primero
        const std::string& l = *it;
        if (l.size() < 24 || l[19] != ' ' || l[20] != '[') { addRow(row++, {L"", L"", W(l)}); continue; }
        const size_t close = l.find(']', 21);
        if (close == std::string::npos) continue;
        addRow(row++, {W(l.substr(0, 19)), W(l.substr(21, close - 21)), W(l.substr(close + 2))});
    }
}

void fillExclusionList() {
    ListView_DeleteAllItems(g.list);
    setColumns({{L"Ruta excluida del analisis", 760}});
    int row = 0;
    for (const auto& p : g.prot.exclusions) addRow(row++, {p.wstring()});
}

/// Reinicia el servicio (si está activo) para que lea la nueva configuración.
void restartProtectionIfRunning();

// ----------------------------------------------------------------------------- navegación y controles

RECT bodyRect(int w, int h) { return R(S(264), S(104), w - S(28), h - S(28)); }
int bottomButtonsTop(int h) { return h - S(28) - S(40); }

void layoutControls() {
    RECT rc;
    GetClientRect(g.main, &rc);
    const int w = rc.right, h = rc.bottom;
    const RECT body = bodyRect(w, h);
    const int listBottom = bottomButtonsTop(h) - S(14);

    int listTop = body.top;
    bool showList = false, showProgress = false;
    if (g.page == PG_SCAN) {
        showList = true;
        showProgress = true;
        listTop = body.top + S(100) + S(16) + S(30) + S(22);
    } else if (g.page == PG_QUARANTINE || g.page == PG_REPORTS || g.page == PG_EXCLUSIONS) {
        showList = true;
    } else if (g.page == PG_THREATS) {
        showList = !g.pending.empty(); // sin amenazas se dibuja un mensaje en su lugar
    }

    ShowWindow(g.list, showList ? SW_SHOW : SW_HIDE);
    ShowWindow(g.progress, showProgress ? SW_SHOW : SW_HIDE);
    if (showList) MoveWindow(g.list, body.left, listTop, body.right - body.left, listBottom - listTop, TRUE);
    if (showProgress) MoveWindow(g.progress, body.left, body.top + S(100) + S(16) + S(30), body.right - body.left, S(8), TRUE);
}

void startCleanAnalysis(bool force); // definida con el resto del codigo de limpieza

void showPage(Page p) {
    g.page = p;
    refreshData();
    if (p == PG_SCAN) fillThreatList();
    else if (p == PG_THREATS) { loadPendingThreats(); fillPendingList(); }
    else if (p == PG_CLEANER) startCleanAnalysis(false);
    else if (p == PG_QUARANTINE) fillQuarantineList();
    else if (p == PG_REPORTS) fillReportList();
    else if (p == PG_SETTINGS) { loadSettings(); g.settingsScroll = 0; }
    else if (p == PG_EXCLUSIONS) { loadSettings(); fillExclusionList(); }
    else if (p == PG_SCHEDULE) loadSettings();
    else if (p == PG_FEEDS) loadSettings();
    layoutControls();
    InvalidateRect(g.main, nullptr, FALSE);
}

// ----------------------------------------------------------------------------- análisis

/// Barra de progreso: indeterminada (marquesina) mientras se desconoce el total; determinada cuando se conoce.
void finishDriveScan();        // definidas con el resto del código de unidades externas
void startNextPendingDrive();

void setProgressMode(bool marquee) {
    LONG_PTR style = GetWindowLongPtrW(g.progress, GWL_STYLE);
    if (marquee) {
        SetWindowLongPtrW(g.progress, GWL_STYLE, style | PBS_MARQUEE);
        SendMessageW(g.progress, PBM_SETMARQUEE, TRUE, 30);
    } else {
        SendMessageW(g.progress, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(g.progress, GWL_STYLE, style & ~static_cast<LONG_PTR>(PBS_MARQUEE));
        SendMessageW(g.progress, PBM_SETRANGE32, 0, 1000);
    }
}

void startScan(std::vector<fs::path> targets, openguard::ScanType type) {
    if (g.scanning.exchange(true)) return;
    if (g.worker.joinable()) g.worker.join();

    g.threats.clear();
    g.processed = 0;
    g.scanStatus = L"Analizando...";
    if (g.page != PG_SCAN) showPage(PG_SCAN); else fillThreatList();
    setProgressMode(true); // mientras se enumeran los archivos el total aún no se conoce
    InvalidateRect(g.main, nullptr, FALSE);

    {
        openguard::ScannerConfig cfg = makeConfig();
        // Rápido y carpeta: se cuenta antes de analizar y el progreso es real. Completo: streaming (discos enormes)
        cfg.precount = (type != openguard::ScanType::Full);
        cfg.onProgress = [](const openguard::ScanProgress& p) {
            if (p.finished || p.processed % 20 == 0) {
                PostMessageW(g.main, WM_APP_PROGRESS, static_cast<WPARAM>(p.processed), static_cast<LPARAM>(p.total ? p.total : p.discovered));
            }
        };
        std::lock_guard<std::mutex> lock(g.scannerMutex);
        g.scanner = std::make_shared<openguard::FileScanner>(g.db, cfg);
        g.scanTotalKnown = cfg.precount;
    }

    g.worker = std::thread([targets = std::move(targets), type]() {
        std::shared_ptr<openguard::FileScanner> sc;
        {
            std::lock_guard<std::mutex> lock(g.scannerMutex);
            sc = g.scanner;
        }
        auto* stats = new openguard::ScanSessionStats();
        try {
            *stats = sc->scanPaths(targets, type, [](const openguard::ScanResult&) {
                const size_t n = ++g.processed;
                if (n % 100 == 0) PostMessageW(g.main, WM_APP_PROGRESS, static_cast<WPARAM>(n), 0);
            });
        } catch (...) {
        }
        PostMessageW(g.main, WM_APP_DONE, 0, reinterpret_cast<LPARAM>(stats));
    });
}

void onScanDone(openguard::ScanSessionStats* stats) {
    std::unique_ptr<openguard::ScanSessionStats> owned(stats);
    if (g.worker.joinable()) g.worker.join();
    g.scanning = false;
    setProgressMode(false);
    SendMessageW(g.progress, PBM_SETPOS, 1000, 0);

    g.threats.clear();
    for (const auto& r : owned->results) {
        if (!r.isThreat()) continue;
        g.threats.push_back(r);
        if (g.history) {
            openguard::HistoryEvent e;
            e.kind = "detection";
            e.level = "ALERT";
            e.path = openguard::paths::toUtf8(r.filePath);
            for (const auto& t : r.threats) { if (!e.threat.empty()) e.threat += ", "; e.threat += t.name; }
            e.action = "detectado (analisis manual)";
            e.sha256 = r.sha256;
            e.details = "riesgo " + std::to_string(r.riskScore) + "/100";
            g.history->record(e);
        }
    }
    // Accion elegida por el usuario ante amenazas: "quarantine" las aisla al terminar el analisis
    int autoIsolated = 0, autoFailed = 0;
    if (g.prot.threatAction == "quarantine" && !g.threats.empty()) isolateAllThreats(autoIsolated, autoFailed, "analisis manual");
    loadPendingThreats();
    if (g.page == PG_SCAN) fillThreatList();

    g.scanStatus = L"Completado: " + std::to_wstring(owned->filesScanned) + L" archivos analizados, " +
                   std::to_wstring(owned->threatsFound) + L" amenazas, " +
                   std::to_wstring(owned->duration.count() / 1000) + L" s";
    iniSetStr(guiIni(), L"stats", L"last_scan", nowText());
    iniSetStr(guiIni(), L"stats", L"last_threats", std::to_wstring(owned->threatsFound));
    {
        const UINT prevTotal = GetPrivateProfileIntW(L"stats", L"total_scanned", 0, guiIni().c_str());
        iniSetStr(guiIni(), L"stats", L"total_scanned", std::to_wstring(static_cast<size_t>(prevTotal) + owned->filesScanned));
    }
    g.homeCacheTick = 0; // fuerza recalcular las cifras de la pantalla de inicio
    if (autoIsolated > 0 || autoFailed > 0) {
        pushToast(L"Analisis completado: " + std::to_wstring(autoIsolated) + L" amenazas aisladas" +
                  (autoFailed ? L", " + std::to_wstring(autoFailed) + L" sin resolver (ver Amenazas)" : L""), autoFailed ? C_WARN : C_OK, 6500);
    } else if (owned->threatsFound > 0) {
        pushToast(L"Analisis completado: " + std::to_wstring(owned->threatsFound) + L" amenazas encontradas. Elija que hacer en Amenazas.", C_BAD, 6500);
    } else {
        pushToast(L"Analisis completado: " + std::to_wstring(owned->filesScanned) + L" archivos, sin amenazas", C_OK);
    }

    refreshData();
    InvalidateRect(g.main, nullptr, FALSE);

    // Análisis de una unidad externa: se muestran las medidas y acciones; luego se sigue con la cola de unidades
    if (g.prot.threatAction == "ask" && owned->threatsFound > 0 && g.driveRoot.empty() && g.page == PG_SCAN && !g.pending.empty()) {
        showPage(PG_THREATS); // el usuario eligio decidir: se le lleva a la lista de amenazas
    }
    if (!g.driveRoot.empty()) {
        finishDriveScan();
        startNextPendingDrive();
    }
}

void isolateSelected() {
    const auto rows = selectedRows();
    if (rows.empty()) {
        MessageBoxW(g.main, L"Seleccione al menos una amenaza de la lista.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
        return;
    }
    int ok = 0, fail = 0;
    std::vector<size_t> done;
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        for (int row : rows) {
            const auto& r = g.threats[static_cast<size_t>(row)];
            const auto& first = r.threats.front();
            if (vault.quarantineFile(r.filePath, first.name, first.severity, r.sha256)) {
                ++ok;
                done.push_back(static_cast<size_t>(row));
                if (g.history) {
                    openguard::HistoryEvent e;
                    e.kind = "quarantine";
                    e.level = "ACTION";
                    e.path = openguard::paths::toUtf8(r.filePath);
                    e.threat = first.name;
                    e.action = "aislado en cuarentena (manual)";
                    e.sha256 = r.sha256;
                    g.history->record(e);
                }
            }
            else ++fail;
        }
    } catch (...) { fail = static_cast<int>(rows.size()); }

    for (auto it = done.rbegin(); it != done.rend(); ++it) g.threats.erase(g.threats.begin() + static_cast<std::ptrdiff_t>(*it));
    fillThreatList();
    refreshData();
    std::wstring msg = std::to_wstring(ok) + L" aislados, " + std::to_wstring(fail) + L" con error.";
    if (fail) msg += L"\n\nCierre el programa que usa el archivo e intentelo de nuevo.";
    MessageBoxW(g.main, msg.c_str(), L"Cuarentena", MB_OK | (fail ? MB_ICONWARNING : MB_ICONINFORMATION));
    InvalidateRect(g.main, nullptr, FALSE);
}

void restartProtectionIfRunning();

/// Acciones sobre las amenazas pendientes seleccionadas: aislar, eliminar o ignorar (excluir).
enum class ThreatOp { Isolate, Delete, Ignore };

void pendingAction(ThreatOp op) {
    const auto rows = selectedRows();
    if (rows.empty()) {
        MessageBoxW(g.main, L"Seleccione una o varias amenazas de la lista (Ctrl o Mayus para varias, o \"Seleccionar todo\").",
                    L"OpenGuard", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring count = std::to_wstring(rows.size());
    if (op == ThreatOp::Delete &&
        MessageBoxW(g.main, (L"Se eliminaran de forma permanente " + count + L" archivo(s). No se podran recuperar. Continuar?").c_str(),
                    L"Eliminar", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
    if (op == ThreatOp::Ignore &&
        MessageBoxW(g.main, (L"OpenGuard dejara de analizar " + count + L" archivo(s) y no volvera a avisar de ellos. "
                             L"Hagalo solo si esta seguro de que son legitimos. Continuar?").c_str(),
                    L"Ignorar", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;

    int ok = 0, fail = 0, skippedSystem = 0;
    bool exclusionsChanged = false;
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        for (int row : rows) {
            if (row < 0 || static_cast<size_t>(row) >= g.pending.size()) continue;
            const auto& e = g.pending[static_cast<size_t>(row)];
            const fs::path p = openguard::paths::fromUtf8(e.path);
            if (op != ThreatOp::Ignore && isProtectedSystemPath(p)) { ++skippedSystem; continue; }

            openguard::HistoryEvent h;
            h.level = "ACTION";
            h.path = e.path;
            h.threat = e.threat;
            h.sha256 = e.sha256;
            bool done = false;
            if (op == ThreatOp::Isolate) {
                done = static_cast<bool>(vault.quarantineFile(p, e.threat.empty() ? "Amenaza.Desconocida" : e.threat, "high", e.sha256));
                h.kind = "quarantine";
                h.action = "aislado en cuarentena (elegido por el usuario)";
            } else if (op == ThreatOp::Delete) {
                std::error_code ec;
                done = fs::remove(p, ec) && !ec;
                h.kind = "delete";
                h.action = "eliminado (elegido por el usuario)";
            } else {
                if (!g.prot.isExcluded(p)) { g.prot.exclusions.push_back(p); exclusionsChanged = true; }
                done = true;
                h.kind = "ignored";
                h.action = "ignorado por el usuario (excluido del analisis)";
            }
            if (done) {
                ++ok;
                if (g.history) g.history->record(h);
            } else {
                ++fail;
            }
        }
    } catch (...) { fail = static_cast<int>(rows.size()) - ok; }

    if (exclusionsChanged) {
        if (g.prot.save()) restartProtectionIfRunning();
        else MessageBoxW(g.main, L"No se pudo guardar la exclusion (ejecute OpenGuard como Administrador).", L"OpenGuard", MB_OK | MB_ICONWARNING);
    }

    loadPendingThreats();
    fillPendingList();
    layoutControls();
    g.homeCacheTick = 0;
    refreshData();

    std::wstring msg = std::to_wstring(ok) + L" resuelta(s)";
    if (fail) msg += L", " + std::to_wstring(fail) + L" con error (archivo en uso o sin permisos: cierre el programa que lo usa e intentelo de nuevo)";
    if (skippedSystem) msg += L".\n" + std::to_wstring(skippedSystem) + L" estan en la carpeta de Windows y no se tocaron: si cree que es un falso positivo use \"Ignorar\"";
    MessageBoxW(g.main, (msg + L".").c_str(), L"Amenazas", MB_OK | ((fail || skippedSystem) ? MB_ICONWARNING : MB_ICONINFORMATION));
    InvalidateRect(g.main, nullptr, FALSE);
}

void openPendingLocation() {
    const auto rows = selectedRows();
    if (rows.empty() || static_cast<size_t>(rows.front()) >= g.pending.size()) {
        MessageBoxW(g.main, L"Seleccione una amenaza de la lista.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring args = L"/select,\"" + openguard::paths::fromUtf8(g.pending[static_cast<size_t>(rows.front())].path).wstring() + L"\"";
    ShellExecuteW(g.main, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
}

void selectAllRows() {
    ListView_SetItemState(g.list, -1, LVIS_SELECTED, LVIS_SELECTED);
    SetFocus(g.list);
}

void quarantineAction(bool restore) {
    const auto rows = selectedRows();
    if (rows.empty()) { MessageBoxW(g.main, L"Seleccione un elemento.", L"OpenGuard", MB_OK | MB_ICONINFORMATION); return; }
    if (!restore && MessageBoxW(g.main, L"Los elementos seleccionados se destruiran de forma permanente. Continuar?",
                                L"Eliminar", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;
    if (restore && MessageBoxW(g.main, L"Restaurar un archivo detectado como amenaza puede infectar el equipo. Continuar?",
                               L"Restaurar", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;

    int ok = 0, fail = 0;
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        for (int row : rows) {
            const std::string qid = g.quarantined[static_cast<size_t>(row)].qid;
            if (restore ? vault.restoreFile(qid) : vault.deletePermanently(qid)) ++ok; else ++fail;
        }
    } catch (...) { fail = static_cast<int>(rows.size()); }

    fillQuarantineList();
    std::wstring msg = std::to_wstring(ok) + L" correctos, " + std::to_wstring(fail) + L" con error.";
    MessageBoxW(g.main, msg.c_str(), L"Cuarentena", MB_OK | (fail ? MB_ICONWARNING : MB_ICONINFORMATION));
    InvalidateRect(g.main, nullptr, FALSE);
}

// ----------------------------------------------------------------------------- limpieza de temporales

struct CleanReport {
    bool cleaned{false};
    std::vector<openguard::cleaner::Usage> usages;
    openguard::cleaner::CleanResult total;
};

/// Calcula el espacio recuperable de cada categoria (en un hilo). La primera vez crea la lista de categorias.
void startCleanAnalysis(bool force) {
    if (g.cleanBusy) return;
    if (g.clean.empty()) {
        for (auto& c : openguard::cleaner::categories()) {
            AppState::CleanRow row;
            row.selected = c.defaultSelected;
            row.cat = std::move(c);
            g.clean.push_back(std::move(row));
        }
    } else if (!force) {
        return;
    }
    if (g.cleanThread.joinable()) g.cleanThread.join();
    g.cleanBusy = true;
    g.cleanCancel = false;
    g.cleanMsg = L"Calculando el espacio recuperable...";
    g.cleanMsgOk = true;
    std::vector<openguard::cleaner::Category> cats;
    for (auto& r : g.clean) { r.measured = false; cats.push_back(r.cat); }
    g.cleanThread = std::thread([cats]() {
        auto* rep = new CleanReport();
        for (const auto& c : cats) rep->usages.push_back(openguard::cleaner::measure(c, &g.cleanCancel));
        PostMessageW(g.main, WM_APP_CLEAN_DONE, 0, reinterpret_cast<LPARAM>(rep));
    });
    InvalidateRect(g.main, nullptr, FALSE);
}

void startClean() {
    if (g.cleanBusy) return;
    std::vector<openguard::cleaner::Category> selected, all;
    uint64_t bytes = 0;
    bool recycle = false;
    for (const auto& r : g.clean) {
        all.push_back(r.cat);
        if (!r.selected) continue;
        selected.push_back(r.cat);
        if (r.measured) bytes += r.usage.bytes;
        if (r.cat.recycleBin) recycle = true;
    }
    if (selected.empty()) {
        MessageBoxW(g.main, L"Marque al menos una categoria para limpiar.", L"Limpieza", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring ask = L"Se eliminaran los archivos de " + std::to_wstring(selected.size()) + L" categoria(s) (aprox. " +
                       openguard::cleaner::formatBytes(bytes) + L").";
    if (recycle) ask += L"\n\nLa Papelera de reciclaje se vaciara y no podra recuperar lo que contiene.";
    ask += L"\n\nLos archivos en uso se respetan. Continuar?";
    if (MessageBoxW(g.main, ask.c_str(), L"Limpieza", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES) return;

    if (g.cleanThread.joinable()) g.cleanThread.join();
    g.cleanBusy = true;
    g.cleanCancel = false;
    g.cleanMsg = L"Limpiando...";
    g.cleanMsgOk = true;
    g.cleanThread = std::thread([selected, all]() {
        auto* rep = new CleanReport();
        rep->cleaned = true;
        for (const auto& c : selected) {
            if (g.cleanCancel) break;
            const auto r = openguard::cleaner::clean(c, &g.cleanCancel);
            rep->total.deleted += r.deleted;
            rep->total.freed += r.freed;
            rep->total.failed += r.failed;
        }
        for (const auto& c : all) rep->usages.push_back(openguard::cleaner::measure(c, &g.cleanCancel));
        PostMessageW(g.main, WM_APP_CLEAN_DONE, 0, reinterpret_cast<LPARAM>(rep));
    });
    InvalidateRect(g.main, nullptr, FALSE);
}

void onCleanDone(CleanReport* r) {
    std::unique_ptr<CleanReport> owned(r);
    if (g.cleanThread.joinable()) g.cleanThread.join();
    g.cleanBusy = false;
    for (size_t i = 0; i < g.clean.size() && i < owned->usages.size(); ++i) {
        g.clean[i].usage = owned->usages[i];
        g.clean[i].measured = true;
    }
    if (owned->cleaned) {
        std::wstring msg = L"Limpieza completada: " + std::to_wstring(owned->total.deleted) + L" archivos eliminados, " +
                           openguard::cleaner::formatBytes(owned->total.freed) + L" liberados";
        if (owned->total.failed) msg += L" (" + std::to_wstring(owned->total.failed) + L" en uso, omitidos)";
        g.cleanMsg = msg + L".";
        g.cleanMsgOk = true;
        pushToast(L"Limpieza: " + openguard::cleaner::formatBytes(owned->total.freed) + L" liberados", C_OK);
        if (g.history) {
            openguard::HistoryEvent e;
            e.level = "INFO";
            e.kind = "cleanup";
            e.threat = "Limpieza de temporales";
            e.action = openguard::paths::toUtf8(fs::path(msg));
            g.history->record(e);
        }
    } else {
        g.cleanMsg.clear();
    }
    InvalidateRect(g.main, nullptr, FALSE);
}

void chooseFolderAndScan() {
    BROWSEINFOW bi{};
    bi.hwndOwner = g.main;
    bi.lpszTitle = L"Seleccione la carpeta a analizar";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    if (PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi)) {
        wchar_t path[MAX_PATH]{};
        if (SHGetPathFromIDListW(pidl, path)) startScan({fs::path(path)}, openguard::ScanType::Custom);
        CoTaskMemFree(pidl);
    }
}

// ----------------------------------------------------------------------------- actualización

void startUpdate() {
    if (g.updating.exchange(true)) return;
    if (g.updater.joinable()) g.updater.join();
    g.updateMsg = L"Descargando firmas...";
    g.updateOk = true;
    InvalidateRect(g.main, nullptr, FALSE);

    g.updater = std::thread([]() {
        auto* res = new openguard::UpdateResult();
        try {
            *res = openguard::updateSignaturesOnline(*g.db);
        } catch (const std::exception& e) {
            res->error = e.what();
        }
        PostMessageW(g.main, WM_APP_UPDATE_DONE, 0, reinterpret_cast<LPARAM>(res));
    });
}

void onUpdateDone(openguard::UpdateResult* res) {
    std::unique_ptr<openguard::UpdateResult> owned(res);
    if (g.updater.joinable()) g.updater.join();
    g.updating = false;
    g.updateOk = owned->ok;
    if (owned->ok) {
        g.updateMsg = L"Actualizacion completada: " + std::to_wstring(owned->inserted) + L" firmas nuevas, " +
                      std::to_wstring(owned->skipped) + L" ya existentes u omitidas.";
        iniSetStr(guiIni(), L"stats", L"last_update", nowText());
        g.homeCacheTick = 0;
        pushToast(L"Firmas actualizadas: " + std::to_wstring(owned->inserted) + L" nuevas", C_OK);
    } else {
        pushToast(L"No se pudo actualizar las firmas", C_WARN);
        g.updateMsg = L"No se pudo actualizar: " + W(owned->error);
    }
    refreshData();
    InvalidateRect(g.main, nullptr, FALSE);
}

void importFromFile() {
    wchar_t file[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.main;
    ofn.lpstrFilter = L"Firmas (*.json;*.txt;*.csv)\0*.json;*.txt;*.csv\0Todos los archivos\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;

    size_t ins = 0, skp = 0;
    bool ok = false;
    const fs::path p(file);
    std::wstring ext = p.extension().wstring();
    for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));
    if (ext == L".json") {
        ok = g.db->importFromJson(p, ins, skp);
    } else {
        std::ifstream in(p, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        ok = g.db->importHashList(ss.str(), "Imported.HashList", "file", ins, skp);
    }
    g.updateOk = ok;
    g.updateMsg = ok ? L"Importacion completada: " + std::to_wstring(ins) + L" firmas nuevas, " + std::to_wstring(skp) + L" omitidas."
                     : L"No se pudo importar el archivo (formato invalido o base de solo lectura).";
    if (ok) iniSetStr(guiIni(), L"stats", L"last_update", nowText());
    refreshData();
    InvalidateRect(g.main, nullptr, FALSE);
}

// ----------------------------------------------------------------------------- fuentes de firmas

void startFeedUpdate() {
    if (g.feedBusy.exchange(true)) return;
    if (g.feedThread.joinable()) g.feedThread.join();
    g.feedMsg = L"Actualizando fuentes (se verifica la firma digital de lo descargado)...";
    g.feedOk = true;
    InvalidateRect(g.main, nullptr, FALSE);

    const openguard::ProtectionSettings prot = g.prot;
    g.feedThread = std::thread([prot]() {
        auto* results = new std::vector<openguard::FeedResult>();
        try {
            openguard::FeedOptions options;
            options.official = true;
            options.rules = prot.feedRules;
            options.bazaar = prot.feedBazaar;
            options.rulesDir = openguard::paths::rulesUpdateDir();
            const openguard::SecretStore secrets;
            *results = openguard::updateFeeds(*g.db, options, secrets);
        } catch (const std::exception& e) {
            openguard::FeedResult r;
            r.feed = "error";
            r.error = e.what();
            results->push_back(r);
        }
        PostMessageW(g.main, WM_APP_FEEDS_DONE, 0, reinterpret_cast<LPARAM>(results));
    });
}

void onFeedsDone(std::vector<openguard::FeedResult>* results) {
    std::unique_ptr<std::vector<openguard::FeedResult>> owned(results);
    if (g.feedThread.joinable()) g.feedThread.join();
    g.feedBusy = false;

    std::wstring msg;
    bool allOk = true, anyOk = false;
    for (const auto& r : *owned) {
        const std::wstring name = r.feed == "official" ? L"Firmas oficiales" : r.feed == "rules" ? L"Reglas YARA" : r.feed == "bazaar" ? L"MalwareBazaar" : W(r.feed);
        if (!msg.empty()) msg += L"\n";
        if (r.ok) {
            anyOk = true;
            msg += name + L": " + std::to_wstring(r.inserted) + (r.feed == "rules" ? L" reglas actualizadas" : L" firmas nuevas") +
                   (r.signatureVerified ? L" (firma verificada)" : L"");
        } else {
            allOk = false;
            msg += name + L": " + W(r.error);
        }
    }
    g.feedMsg = msg.empty() ? L"No hay fuentes habilitadas." : msg;
    g.feedOk = allOk;
    if (anyOk) {
        iniSetStr(guiIni(), L"stats", L"last_update", nowText());
        g.homeCacheTick = 0;
        loadYaraCount();
        refreshData();
    }
    pushToast(allOk ? L"Fuentes actualizadas" : L"Actualizacion con errores (ver detalle)", allOk ? C_OK : C_WARN);
    InvalidateRect(g.main, nullptr, FALSE);
}

/// Guarda como clave de abuse.ch el texto del portapapeles (cifrado con DPAPI). Evita pedir texto en un cuadro propio.
void pasteFeedKeyFromClipboard() {
    std::string key;
    if (OpenClipboard(g.main)) {
        if (HANDLE h = GetClipboardData(CF_UNICODETEXT)) {
            if (const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h))) {
                key = openguard::paths::toUtf8(fs::path(std::wstring(p)));
                GlobalUnlock(h);
            }
        }
        CloseClipboard();
    }
    const auto b = key.find_first_not_of(" \t\r\n");
    const auto e = key.find_last_not_of(" \t\r\n");
    key = (b == std::string::npos) ? std::string() : key.substr(b, e - b + 1);

    const bool plausible = key.size() >= 16 && key.size() <= 200 &&
                           std::all_of(key.begin(), key.end(), [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
    if (!plausible) {
        MessageBoxW(g.main, L"El portapapeles no contiene una clave valida de abuse.ch.\n\nCopie la clave (Auth-Key de su cuenta en abuse.ch) y pulse de nuevo el boton.",
                    L"Clave de abuse.ch", MB_OK | MB_ICONINFORMATION);
        return;
    }
    openguard::SecretStore secrets;
    if (secrets.set(openguard::kAbuseChSecret, key)) {
        pushToast(L"Clave guardada cifrada con DPAPI", C_OK);
    } else {
        MessageBoxW(g.main, L"No se pudo guardar la clave (ejecute OpenGuard como Administrador).", L"Clave de abuse.ch", MB_OK | MB_ICONWARNING);
    }
    InvalidateRect(g.main, nullptr, FALSE);
}

// ----------------------------------------------------------------------------- actualización del programa

void showBalloon(const std::wstring& title, const std::wstring& body, DWORD icon);

void startAppCheck(bool silent) {
    if (g.appBusy.exchange(true)) return;
    if (g.appThread.joinable()) g.appThread.join();
    g.appSilentCheck = silent;
    if (!silent) { g.appMsg = L"Buscando actualizaciones..."; InvalidateRect(g.main, nullptr, FALSE); }

    g.appThread = std::thread([]() {
        auto* info = new openguard::AppUpdateInfo();
        try {
            *info = openguard::checkForAppUpdate(OPENGUARD_VERSION);
        } catch (const std::exception& e) {
            info->error = e.what();
        }
        PostMessageW(g.main, WM_APP_APPCHECK_DONE, 0, reinterpret_cast<LPARAM>(info));
    });
}

void onAppCheckDone(openguard::AppUpdateInfo* info) {
    std::unique_ptr<openguard::AppUpdateInfo> owned(info);
    if (g.appThread.joinable()) g.appThread.join();
    g.appBusy = false;

    const bool wasNew = g.appInfo.available;
    g.appInfo = *owned;
    g.appChecked = owned->ok;
    iniSetStr(guiIni(), L"stats", L"last_app_check", nowText());

    if (!owned->ok) {
        g.appMsg = g.appSilentCheck ? L"" : L"No se pudo buscar actualizaciones: " + W(owned->error);
    } else if (owned->available) {
        g.appMsg = L"Hay una nueva version disponible: " + W(owned->latestVersion);
        if (!wasNew && g.settings.notify) {
            showBalloon(L"OpenGuard: nueva version " + W(owned->latestVersion),
                        L"Abra OpenGuard > Actualizacion para descargarla e instalarla.", NIIF_INFO);
        }
    } else {
        g.appMsg = g.appSilentCheck ? L"" : L"Tiene la version mas reciente (" + W(std::string(OPENGUARD_VERSION)) + L").";
    }
    InvalidateRect(g.main, nullptr, FALSE);
}

void startAppInstall() {
    if (!g.appInfo.available || g.appBusy.exchange(true)) return;
    if (g.appThread.joinable()) g.appThread.join();
    g.appMsg = L"Descargando instalador (puede tardar unos segundos)...";
    InvalidateRect(g.main, nullptr, FALSE);

    const openguard::AppUpdateInfo info = g.appInfo;
    g.appThread = std::thread([info]() {
        auto* res = new DownloadResult();
        try {
            // No se descarga en Temp: el servicio vigila esa carpeta y podia aislar el instalador (sin firma digital)
            // antes de ejecutarlo. ProgramData\OpenGuard\updates no se vigila y solo la escribe un administrador.
            const fs::path dir = openguard::paths::dataDir() / L"updates";
            std::error_code mkec;
            fs::create_directories(dir, mkec);
            const fs::path dest = dir / fs::path(W(info.installerName.empty() ? std::string("OpenGuard_Setup.exe") : info.installerName));
            std::string err;
            res->ok = openguard::downloadInstaller(info, dest, err);
            res->path = dest.wstring();
            res->error = W(err);
        } catch (const std::exception& e) {
            res->error = W(e.what());
        }
        PostMessageW(g.main, WM_APP_APPDL_DONE, 0, reinterpret_cast<LPARAM>(res));
    });
}

void onAppDownloadDone(DownloadResult* res) {
    std::unique_ptr<DownloadResult> owned(res);
    if (g.appThread.joinable()) g.appThread.join();
    g.appBusy = false;

    if (!owned->ok) {
        g.appMsg = L"No se pudo descargar la actualizacion: " + owned->error;
        InvalidateRect(g.main, nullptr, FALSE);
        return;
    }
    g.appMsg = L"Instalador descargado y verificado.";
    if (MessageBoxW(g.main, L"El instalador se descargo y su integridad fue verificada.\n\nOpenGuard se cerrara para actualizarse. Continuar?",
                    L"Actualizar OpenGuard", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        std::error_code ec;
        if (!fs::exists(owned->path, ec)) {
            MessageBoxW(g.main, (L"El instalador ya no esta en:\n" + owned->path +
                                 L"\n\nPudo ser eliminado o aislado por otro programa de seguridad. Descarguelo de nuevo o desde la pagina de versiones de GitHub.").c_str(),
                        L"OpenGuard", MB_OK | MB_ICONWARNING);
        } else {
            const INT_PTR rc = reinterpret_cast<INT_PTR>(ShellExecuteW(g.main, L"open", owned->path.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
            if (rc > 32) {
                PostMessageW(g.main, WM_CLOSE, 0, 0);
            } else {
                MessageBoxW(g.main, (L"No se pudo iniciar el instalador (codigo " + std::to_wstring(static_cast<long long>(rc)) +
                                     L"). Puede ejecutarlo manualmente desde:\n" + owned->path).c_str(),
                            L"OpenGuard", MB_OK | MB_ICONWARNING);
            }
        }
    }
    InvalidateRect(g.main, nullptr, FALSE);
}

// ----------------------------------------------------------------------------- bandeja y notificaciones

std::uintmax_t g_logOffset = 0;
NOTIFYICONDATAW g_tray{};

void openLog() {
    const fs::path log = openguard::paths::logsDir() / "service.log";
    std::error_code ec;
    if (!fs::exists(log, ec)) {
        MessageBoxW(g.main, L"Aun no hay registro del servicio.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring args = L"\"" + log.wstring() + L"\"";
    ShellExecuteW(g.main, L"open", L"notepad.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
}

void addTrayIcon() {
    g_tray = {};
    g_tray.cbSize = sizeof(g_tray);
    g_tray.hWnd = g.main;
    g_tray.uID = 1;
    g_tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_tray.uCallbackMessage = WM_APP_TRAY;
    g_tray.hIcon = g.icon ? g.icon : LoadIconW(nullptr, IDI_SHIELD);
    lstrcpynW(g_tray.szTip, L"OpenGuard Antivirus", static_cast<int>(std::size(g_tray.szTip)));
    Shell_NotifyIconW(NIM_ADD, &g_tray);

    std::error_code ec;
    const fs::path log = openguard::paths::logsDir() / "service.log";
    g_logOffset = fs::exists(log, ec) ? fs::file_size(log, ec) : 0; // solo eventos posteriores al arranque
}

void removeTrayIcon() { Shell_NotifyIconW(NIM_DELETE, &g_tray); }

void showBalloon(const std::wstring& title, const std::wstring& body, DWORD icon) {
    NOTIFYICONDATAW n = g_tray;
    n.uFlags = NIF_INFO;
    n.dwInfoFlags = icon;
    lstrcpynW(n.szInfoTitle, title.c_str(), static_cast<int>(std::size(n.szInfoTitle)));
    lstrcpynW(n.szInfo, body.c_str(), static_cast<int>(std::size(n.szInfo)));
    Shell_NotifyIconW(NIM_MODIFY, &n);
}

void pollServiceLog() {
    const fs::path log = openguard::paths::logsDir() / "service.log";
    std::error_code ec;
    if (!fs::exists(log, ec)) return;
    const std::uintmax_t size = fs::file_size(log, ec);
    if (ec) return;
    if (size < g_logOffset) g_logOffset = 0;
    if (size == g_logOffset) return;

    std::ifstream in(log, std::ios::binary);
    if (!in.is_open()) return;
    in.seekg(static_cast<std::streamoff>(g_logOffset));
    std::string line, lastAlert;
    int alerts = 0;
    while (std::getline(in, line)) {
        if (line.find("[ALERT]") != std::string::npos || line.find("[ACTION]") != std::string::npos) {
            lastAlert = line;
            ++alerts;
        }
    }
    g_logOffset = size;

    if (alerts > 0) pushToast(W(lastAlert.size() > 20 ? lastAlert.substr(20) : lastAlert), C_BAD, 6500);
    if (alerts > 0 && g.settings.notify) {
        const std::string body = lastAlert.size() > 20 ? lastAlert.substr(20) : lastAlert;
        showBalloon(alerts > 1 ? L"OpenGuard: " + std::to_wstring(alerts) + L" alertas" : L"OpenGuard: alerta de seguridad",
                    W(body), NIIF_WARNING);
        if (g.page == PG_REPORTS) fillReportList();
    }
}

// ----------------------------------------------------------------------------- páginas (dibujo)

struct Status { COLORREF color; std::wstring title, subtitle, action; int actionId; };

Status computeStatus() {
    if (g.svc == Svc::NotInstalled) {
        return {C_BAD, L"Proteccion en tiempo real no instalada",
                L"Su equipo no esta protegido de forma continua. Active la proteccion para analizar archivos nuevos automaticamente.",
                L"Activar proteccion", ID_TOGGLE_PROTECTION};
    }
    if (g.svc == Svc::Stopped) {
        return {C_BAD, L"La proteccion esta desactivada",
                L"El servicio de OpenGuard esta detenido. Active la proteccion para volver a estar protegido.",
                L"Activar proteccion", ID_TOGGLE_PROTECTION};
    }
    if (g.sigCount <= 3) {
        return {C_WARN, L"Se recomienda actualizar las firmas",
                L"La base de firmas solo contiene firmas de prueba. Actualicela para detectar amenazas reales.",
                L"Actualizar ahora", ID_FIX};
    }
    return {C_OK, L"Esta protegido", L"La proteccion en tiempo real esta activa y la base de firmas esta cargada.", L"", 0};
}

void paintSidebar(HDC hdc, int h) {
    const int sw = S(232);

    // Fondo con degradado vertical y borde derecho fino
    {
        Gdiplus::LinearGradientBrush br(Gdiplus::PointF(0.0f, 0.0f), Gdiplus::PointF(0.0f, static_cast<float>(h)),
                                        gc(RGB(13, 18, 32)), gc(RGB(8, 10, 19)));
        g.gfx->FillRectangle(&br, 0, 0, sw, h);
        Gdiplus::Pen edge(gc(C_BORDER, 200), 1.0f);
        g.gfx->DrawLine(&edge, sw - 1, 0, sw - 1, h);
    }

    flushGdi();
    if (g.icon) DrawIconEx(hdc, S(20), S(22), g.icon, S(44), S(44), 0, nullptr, DI_NORMAL);
    text(hdc, L"OPENGUARD", R(S(72), S(22), sw - S(8), S(46)), g.fH2, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"A N T I V I R U S", R(S(72), S(46), sw - S(8), S(66)), g.fSmall, C_ACCENT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    static const wchar_t* names[PG_COUNT] = {L"Inicio", L"Analisis", L"Amenazas", L"Limpieza", L"Actualizacion", L"Cuarentena", L"Informes", L"Configuracion"};
    static const wchar_t* glyphs[PG_COUNT] = {L"\xE80F", L"\xE721", L"\xE7BA", L"\xE74D", L"\xE895", L"\xE72E", L"\xE8A5", L"\xE713"};
    int y = S(104);
    for (int i = 0; i < PG_COUNT; ++i) {
        RECT item = R(S(10), y, sw - S(10), y + S(46));
        const bool sel = (g.page == i) || (i == PG_SETTINGS && (g.page == PG_EXCLUSIONS || g.page == PG_SCHEDULE)) ||
                          (i == PG_UPDATE && g.page == PG_FEEDS);
        const bool hot = isHot(NAV_BASE + i);
        if (sel || hot) {
            Gdiplus::GraphicsPath p;
            addRoundPath(p, item, S(12));
            if (sel) {
                Gdiplus::LinearGradientBrush br(Gdiplus::PointF(static_cast<float>(item.left), 0.0f),
                                                Gdiplus::PointF(static_cast<float>(item.right), 0.0f), gc(C_ACCENT, 46), gc(C_VIOLET, 22));
                g.gfx->FillPath(&br, &p);
                Gdiplus::Pen pen(gc(C_ACCENT, 90), 1.0f);
                g.gfx->DrawPath(&pen, &p);
                // Barra lateral luminosa
                Gdiplus::LinearGradientBrush bar(Gdiplus::PointF(0.0f, static_cast<float>(item.top)),
                                                 Gdiplus::PointF(0.0f, static_cast<float>(item.bottom)), gc(C_ACCENT), gc(C_VIOLET));
                g.gfx->FillRectangle(&bar, 0, static_cast<int>(item.top) + S(8), S(4), S(30));
            } else {
                Gdiplus::SolidBrush br(gc(C_WHITE, 14));
                g.gfx->FillPath(&br, &p);
            }
        }
        text(hdc, glyphs[i], R(S(26), y, S(54), y + S(46)), g.fIcon, sel ? C_ACCENT : (hot ? C_TEXT : C_SIDE_TEXT), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, names[i], R(S(64), y, sw - S(8), y + S(46)), g.fBody, sel ? C_TEXT : (hot ? C_TEXT : C_SIDE_TEXT), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        addHit(item, NAV_BASE + i);
        y += S(52);
    }

    // Estado del servicio y versión al pie
    const bool on = (g.svc == Svc::Running);
    const COLORREF stateColor = on ? C_OK : C_BAD;
    Gdiplus::SolidBrush halo(gc(stateColor, 50));
    g.gfx->FillEllipse(&halo, S(20), h - S(76), S(18), S(18));
    Gdiplus::SolidBrush dot(gc(stateColor));
    g.gfx->FillEllipse(&dot, S(24), h - S(72), S(10), S(10));
    text(hdc, on ? L"Proteccion activa" : L"Proteccion inactiva", R(S(46), h - S(80), sw - S(8), h - S(58)), g.fSmall, C_SIDE_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, W(std::string("Version ") + OPENGUARD_VERSION), R(S(24), h - S(48), sw - S(8), h - S(26)), g.fSmall, RGB(96, 108, 134), DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
}

void pageHeader(HDC hdc, int w, const std::wstring& title, const std::wstring& subtitle) {
    text(hdc, title, R(S(264), S(24), w - S(28), S(66)), g.fH1, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, subtitle, R(S(264), S(66), w - S(28), S(90)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    Gdiplus::LinearGradientBrush bar(Gdiplus::PointF(static_cast<float>(S(264)), 0.0f), Gdiplus::PointF(static_cast<float>(S(264) + S(70)), 0.0f),
                                     gc(C_ACCENT), gc(C_VIOLET));
    g.gfx->FillRectangle(&bar, S(264), S(94), S(70), S(3));
}

std::wstring isolationText() {
    const fs::path ini = openguard::paths::dataDir() / L"status.ini";
    const std::wstring mode = iniGetStr(ini, L"isolation", L"mode", L"");
    const bool netBlock = iniGetBool(ini, L"isolation", L"network_block", false);
    if (mode == L"full") return netBlock ? L"Activo: proceso de bajo privilegio y sin red" : L"Activo: bajo privilegio (red del worker NO bloqueada)";
    if (mode == L"degraded") return L"Degradado: sin token restringido (limitado por Job Object y mitigaciones)";
    if (mode == L"missing") return L"No disponible: falta openguard_worker.exe";
    if (mode == L"off") return L"Desactivado en la configuracion";
    return L"Sin datos (inicie la proteccion en tiempo real)";
}

std::wstring scheduleSummary(); // definida con la pantalla de programación

/// Datos de la pantalla de inicio (se recalculan como máximo cada 3 s para que la animación sea fluida).
void refreshHomeCache() {
    const ULONGLONG now = GetTickCount64();
    if (g.homeCacheTick != 0 && now - g.homeCacheTick < 3000) return;
    g.homeCacheTick = now;

    g.isoText = isolationText();
    g.lastScanText = iniGetStr(guiIni(), L"stats", L"last_scan", L"Nunca");
    g.lastUpdateText = iniGetStr(guiIni(), L"stats", L"last_update", L"Nunca");
    g.totalScanned = static_cast<size_t>(GetPrivateProfileIntW(L"stats", L"total_scanned", 0, guiIni().c_str()));

    if (!g.history) return;
    g.threatsBlocked = g.history->count("quarantine");
    g.threatsDetected = g.history->count("detection");
    loadPendingThreats();
    g.feed = g.history->recent(6);

    // Detecciones de los últimos 7 días (día de calendario local)
    std::fill(std::begin(g.chartCounts), std::end(g.chartCounts), 0);
    const std::time_t nowT = std::time(nullptr);
    std::tm today{};
    localtime_s(&today, &nowT);
    today.tm_hour = today.tm_min = today.tm_sec = 0;
    today.tm_isdst = -1;
    const std::time_t todayStart = std::mktime(&today);
    for (const auto& e : g.history->recent(3000)) {
        if (e.kind != "detection" && e.kind != "ransomware") continue;
        const std::time_t t = openguard::parseLocalStamp(e.timestamp);
        if (t == 0 || t > nowT + 60) continue;
        const int daysAgo = static_cast<int>(std::floor(std::difftime(todayStart, t) / 86400.0 + 0.999999));
        const int d = std::max(0, daysAgo);
        if (d < 7) g.chartCounts[6 - d]++;
    }
}

void paintHome(HDC hdc, int w, int h) {
    refreshHomeCache();
    pageHeader(hdc, w, L"Inicio", L"Estado general de la proteccion de su equipo");
    const RECT body = bodyRect(w, h);
    const int bw = body.right - body.left;
    const Status st = computeStatus();
    int y = body.top;

    // Aviso de nueva versión del programa
    if (g.appInfo.available) {
        RECT strip = R(body.left, y, body.right, y + S(44));
        glassPanel(strip, S(12), C_ACCENT, 170);
        text(hdc, L"Nueva version disponible: OpenGuard " + W(g.appInfo.latestVersion),
             R(strip.left + S(18), strip.top, strip.right - S(210), strip.bottom), g.fBold, C_ACCENT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        drawButton(hdc, R(strip.right - S(190), strip.top + S(5), strip.right - S(8), strip.bottom - S(5)), L"Ver actualizacion", NAV_UPDATE, BS_PRIMARY);
        y += S(56);
    }

    // ---- Panel principal: anillo de estado animado, mensaje y botón grande de escanear
    const int heroH = S(196);
    const RECT hero = R(body.left, y, body.right, y + heroH);
    glassPanel(hero, S(20));
    {
        Gdiplus::GraphicsPath p;
        addRoundPath(p, hero, S(20));
        Gdiplus::LinearGradientBrush tint(Gdiplus::PointF(static_cast<float>(hero.left), 0.0f),
                                          Gdiplus::PointF(static_cast<float>(hero.left) + bw * 0.7f, 0.0f), gc(st.color, 48), gc(st.color, 0));
        g.gfx->FillPath(&tint, &p);
    }
    const int ringR = S(58);
    const int cx = hero.left + S(108), cy = hero.top + heroH / 2;
    g.animRect = R(cx - ringR - S(40), cy - ringR - S(40), cx + ringR + S(40), cy + ringR + S(40));
    drawStatusRing(hdc, cx, cy, ringR, st.color, g.animPhase);

    const int tx = hero.left + S(220);
    const int textRight = hero.right - S(276);
    text(hdc, st.title, R(tx, hero.top + S(24), textRight, hero.top + S(70)), g.fBig, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    text(hdc, st.subtitle, R(tx, hero.top + S(74), textRight, hero.top + S(122)), g.fBody, C_MUTED);
    const int by = hero.bottom - S(64);
    drawButton(hdc, R(tx, by, tx + S(172), by + S(44)), g.scanning ? L"ANALIZANDO..." : L"ESCANEAR", ID_SCAN_QUICK, BS_PRIMARY, !g.scanning);
    drawButton(hdc, R(tx + S(184), by, tx + S(184) + S(140), by + S(44)), L"Completo", ID_SCAN_FULL, BS_SECONDARY, !g.scanning);
    if (st.actionId != 0) {
        drawButton(hdc, R(tx + S(336), by, textRight + S(20), by + S(44)), st.action, st.actionId, BS_SECONDARY);
    }

    // Indicadores de estado (píldoras)
    {
        const bool svcOn = (g.svc == Svc::Running);
        const bool isoOn = g.isoText.rfind(L"Activo", 0) == 0;
        const wchar_t* usb = g.prot.usbMode == "auto" ? L"Automatico" : g.prot.usbMode == "off" ? L"Desactivado" : L"Preguntar";
        struct Chip { const wchar_t* label; std::wstring value; COLORREF color; };
        const Chip chips[] = {
            {L"Tiempo real", svcOn ? L"Activo" : L"Inactivo", svcOn ? C_OK : C_BAD},
            {L"Descargas", g.prot.scanDownloads ? L"Vigiladas" : L"Sin vigilar", g.prot.scanDownloads ? C_OK : C_WARN},
            {L"Unidades USB", usb, g.prot.usbMode == "off" ? C_WARN : C_OK},
            {L"Aislamiento", isoOn ? L"Activo" : L"Revisar", isoOn ? C_OK : C_WARN},
        };
        int cy2 = hero.top + S(18);
        const int cxL = hero.right - S(256);
        for (const auto& c : chips) {
            const RECT pill = R(cxL, cy2, hero.right - S(18), cy2 + S(34));
            glassPanel(pill, S(17));
            Gdiplus::SolidBrush halo(gc(c.color, 50));
            g.gfx->FillEllipse(&halo, static_cast<int>(pill.left) + S(10), static_cast<int>(pill.top) + S(9), S(16), S(16));
            Gdiplus::SolidBrush dot(gc(c.color));
            g.gfx->FillEllipse(&dot, static_cast<int>(pill.left) + S(14), static_cast<int>(pill.top) + S(13), S(8), S(8));
            text(hdc, c.label, R(pill.left + S(34), pill.top, pill.left + S(120), pill.bottom), g.fSmall, C_MUTED, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            text(hdc, c.value, R(pill.left + S(118), pill.top, pill.right - S(10), pill.bottom), g.fSmall, c.color, DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            cy2 += S(42);
        }
    }

    // ---- Tarjetas de estadísticas
    y = hero.bottom + S(16);
    const int sh = S(100), gap = S(16);
    const int cw = (bw - 2 * gap) / 3;
    auto stat = [&](int idx, const wchar_t* title, const std::wstring& value, const std::wstring& sub, COLORREF color, int id) {
        const RECT rc = R(body.left + idx * (cw + gap), y, body.left + idx * (cw + gap) + cw, y + sh);
        const bool hot = isHot(id);
        if (hot) glowRound(rc, S(16), color, 3, 80);
        glassPanel(rc, S(16), hot ? color : C_BORDER, 255);
        text(hdc, title, R(rc.left + S(18), rc.top + S(12), rc.right - S(12), rc.top + S(30)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, value, R(rc.left + S(18), rc.top + S(28), rc.right - S(12), rc.top + S(68)), g.fBig, color, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, sub, R(rc.left + S(18), rc.bottom - S(26), rc.right - S(12), rc.bottom - S(8)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
        addHit(rc, id);
    };
    stat(0, L"ARCHIVOS ANALIZADOS", std::to_wstring(g.totalScanned), L"Ultimo analisis: " + g.lastScanText, C_ACCENT, NAV_SCAN);
    stat(1, L"AMENAZAS PENDIENTES", std::to_wstring(g.pending.size()),
         L"Aisladas: " + std::to_wstring(g.threatsBlocked) + L"  |  Detectadas: " + std::to_wstring(g.threatsDetected) +
         (g.pending.empty() ? L"" : L"  -  pulse para revisar"), g.pending.empty() ? C_OK : C_BAD, NAV_THREATS);
    stat(2, L"FIRMAS DE AMENAZAS", std::to_wstring(g.sigCount), L"Actualizado: " + g.lastUpdateText, C_VIOLET, NAV_UPDATE);

    // ---- Actividad en vivo y gráfico de detecciones
    y += sh + S(16);
    const int areaH = std::min<int>(S(230), body.bottom - y);
    if (areaH < S(120)) return; // ventana muy baja: se omite esta franja

    const int feedW = static_cast<int>(bw * 0.58);
    const RECT feedR = R(body.left, y, body.left + feedW, y + areaH);
    const RECT chartR = R(feedR.right + S(16), y, body.right, y + areaH);
    glassPanel(feedR, S(16));
    glassPanel(chartR, S(16));

    text(hdc, L"ACTIVIDAD EN VIVO", R(feedR.left + S(18), feedR.top + S(12), feedR.right - S(12), feedR.top + S(32)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    if (g.feed.empty()) {
        text(hdc, L"Sin actividad registrada todavia. Los analisis, detecciones y acciones aparecen aqui.",
             R(feedR.left + S(18), feedR.top + S(44), feedR.right - S(18), feedR.bottom - S(10)), g.fBody, C_MUTED);
    } else {
        int ry = feedR.top + S(40);
        const int maxRows = std::max<int>(1, static_cast<int>((feedR.bottom - ry - S(8)) / S(30)));
        int shown = 0;
        for (const auto& e : g.feed) {
            if (shown++ >= maxRows) break;
            COLORREF dotColor = C_MUTED;
            if (e.kind == "detection" || e.kind == "ransomware") dotColor = C_BAD;
            else if (e.kind == "quarantine") dotColor = C_WARN;
            else if (e.kind == "scan") dotColor = C_ACCENT;
            else if (e.kind == "usb_repair") dotColor = C_OK;
            Gdiplus::SolidBrush halo(gc(dotColor, 50));
            g.gfx->FillEllipse(&halo, feedR.left + S(16), ry + S(6), S(16), S(16));
            Gdiplus::SolidBrush dot(gc(dotColor));
            g.gfx->FillEllipse(&dot, feedR.left + S(20), ry + S(10), S(8), S(8));
            const std::wstring when = W(e.timestamp.size() >= 16 ? e.timestamp.substr(11, 5) : e.timestamp);
            text(hdc, when, R(feedR.left + S(40), ry, feedR.left + S(90), ry + S(28)), g.fSmall, C_MUTED, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            const std::wstring msg = W(e.threat.empty() ? e.kind : e.threat) + (e.action.empty() ? L"" : L"  -  " + W(e.action));
            text(hdc, msg, R(feedR.left + S(92), ry, feedR.right - S(14), ry + S(28)), g.fBody, C_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
            ry += S(30);
        }
    }

    text(hdc, L"DETECCIONES (7 DIAS)", R(chartR.left + S(18), chartR.top + S(12), chartR.right - S(12), chartR.top + S(32)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    {
        int maxV = 1;
        for (int v : g.chartCounts) maxV = std::max(maxV, v);
        const int plotL = chartR.left + S(22), plotR = chartR.right - S(22);
        const int plotTop = chartR.top + S(48), plotBottom = chartR.bottom - S(34);
        const int slot = (plotR - plotL) / 7;
        static const wchar_t kDay[7] = {L'D', L'L', L'M', L'X', L'J', L'V', L'S'};
        const std::time_t nowT = std::time(nullptr);

        Gdiplus::Pen axis(gc(C_BORDER), 1.0f);
        g.gfx->DrawLine(&axis, plotL, plotBottom, plotR, plotBottom);
        for (int i = 0; i < 7; ++i) {
            const int bx = plotL + i * slot + slot / 4;
            const int bwid = slot / 2;
            const int v = g.chartCounts[i];
            const int bh = v == 0 ? S(3) : std::max(S(6), (plotBottom - plotTop) * v / maxV);
            const RECT bar = R(bx, plotBottom - bh, bx + bwid, plotBottom);
            Gdiplus::GraphicsPath p;
            addRoundPath(p, bar, std::min(S(4), bwid / 2));
            if (v == 0) {
                Gdiplus::SolidBrush empty(gc(C_BORDER));
                g.gfx->FillPath(&empty, &p);
            } else {
                Gdiplus::LinearGradientBrush br(Gdiplus::PointF(0.0f, static_cast<float>(bar.top)), Gdiplus::PointF(0.0f, static_cast<float>(bar.bottom)),
                                                gc(C_ACCENT), gc(C_VIOLET));
                g.gfx->FillPath(&br, &p);
                text(hdc, std::to_wstring(v), R(bx - S(8), bar.top - S(20), bx + bwid + S(8), bar.top - S(2)), g.fSmall, C_TEXT, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
            }
            std::tm tmDay{};
            const std::time_t dayT = nowT - static_cast<std::time_t>(6 - i) * 86400;
            localtime_s(&tmDay, &dayT);
            const std::wstring lbl(1, kDay[tmDay.tm_wday % 7]);
            text(hdc, lbl, R(bx - S(6), plotBottom + S(6), bx + bwid + S(6), plotBottom + S(26)), g.fSmall, i == 6 ? C_ACCENT : C_MUTED, DT_CENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
    }
}

void paintScan(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Analisis", L"Busque amenazas en archivos y carpetas");
    const RECT body = bodyRect(w, h);
    const int gap = S(16);
    const int cw = (body.right - body.left - 2 * gap) / 3;
    const int top = body.top, chh = S(100);
    drawCardButton(hdc, R(body.left, top, body.left + cw, top + chh), L"Analisis rapido", L"Zonas de mayor riesgo del equipo", ID_SCAN_QUICK, !g.scanning);
    drawCardButton(hdc, R(body.left + cw + gap, top, body.left + 2 * cw + gap, top + chh), L"Analisis completo", L"Todas las unidades (puede tardar)", ID_SCAN_FULL, !g.scanning);
    drawCardButton(hdc, R(body.left + 2 * (cw + gap), top, body.right, top + chh), L"Carpeta personalizada", L"Elija una carpeta o unidad", ID_SCAN_FOLDER, !g.scanning);

    const std::wstring msg = g.scanStatus.empty() ? L"Elija un tipo de analisis para comenzar." : g.scanStatus;
    text(hdc, msg, R(body.left, top + chh + S(14), body.right, top + chh + S(40)), g.fBody, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    const int by = bottomButtonsTop(h);
    drawButton(hdc, R(body.left, by, body.left + S(220), by + S(40)), L"Aislar seleccionados", ID_ISOLATE, BS_PRIMARY, !g.scanning && !g.threats.empty());
    drawButton(hdc, R(body.left + S(232), by, body.left + S(232) + S(180), by + S(40)), L"Cancelar analisis", ID_CANCEL, BS_SECONDARY, g.scanning);
}

void paintUpdate(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Actualizacion", L"Mantenga al dia las firmas de amenazas y el programa");
    const RECT body = bodyRect(w, h);

    // --- Tarjeta 1: base de firmas
    RECT card = R(body.left, body.top, body.right, body.top + S(176));
    drawCard(hdc, card);
    text(hdc, std::to_wstring(g.sigCount), R(card.left + S(24), card.top + S(12), card.left + S(300), card.top + S(62)), g.fBig, C_ACCENT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"firmas cargadas", R(card.left + S(24), card.top + S(60), card.left + S(300), card.top + S(84)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"Reglas YARA: " + std::to_wstring(g.yaraCount), R(card.left + S(320), card.top + S(22), card.right - S(20), card.top + S(48)), g.fBody, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"Ultima actualizacion: " + iniGetStr(guiIni(), L"stats", L"last_update", L"Nunca"),
         R(card.left + S(320), card.top + S(52), card.right - S(20), card.top + S(78)), g.fBody, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    drawButton(hdc, R(card.left + S(24), card.bottom - S(56), card.left + S(24) + S(190), card.bottom - S(16)),
               g.updating ? L"Actualizando..." : L"Actualizar firmas", ID_UPDATE_NOW, BS_PRIMARY, !g.updating);
    drawButton(hdc, R(card.left + S(228), card.bottom - S(56), card.left + S(228) + S(210), card.bottom - S(16)),
               L"Importar desde archivo...", ID_IMPORT_FILE, BS_SECONDARY, !g.updating);
    drawButton(hdc, R(card.left + S(450), card.bottom - S(56), card.left + S(450) + S(250), card.bottom - S(16)),
               L"Fuentes automaticas...", ID_FEEDS_OPEN, BS_SECONDARY);
    if (!g.updateMsg.empty()) {
        text(hdc, g.updateMsg, R(body.left, card.bottom + S(8), body.right, card.bottom + S(32)), g.fBold, g.updateOk ? C_OK : C_BAD, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    }

    // --- Tarjeta 2: version del programa
    RECT app = R(body.left, card.bottom + S(42), body.right, card.bottom + S(42) + S(190));
    if (app.bottom > body.bottom + S(10)) app.bottom = body.bottom + S(10);
    drawCard(hdc, app);
    text(hdc, L"Version del programa", R(app.left + S(24), app.top + S(14), app.right - S(20), app.top + S(40)), g.fH2, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, W(std::string("Instalada: ") + OPENGUARD_VERSION), R(app.left + S(24), app.top + S(44), app.left + S(300), app.top + S(70)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    std::wstring status;
    COLORREF statusColor = C_MUTED;
    if (g.appInfo.available) {
        status = L"Nueva version disponible: " + W(g.appInfo.latestVersion);
        statusColor = C_ACCENT;
    } else if (!g.appMsg.empty()) {
        status = g.appMsg;
        statusColor = g.appChecked ? C_OK : C_MUTED;
    } else {
        status = L"Pulse \"Buscar actualizaciones\" para comprobar si hay una version mas reciente.";
    }
    if (g.appInfo.available && !g.appMsg.empty() && g.appMsg.rfind(L"Hay una nueva", 0) != 0) status += L"\n" + g.appMsg;
    text(hdc, status, R(app.left + S(320), app.top + S(14), app.right - S(20), app.top + S(100)), g.fBold, statusColor);

    const int by = app.bottom - S(56);
    int bx = app.left + S(24);
    drawButton(hdc, R(bx, by, bx + S(210), by + S(40)), g.appBusy ? L"Espere..." : L"Buscar actualizaciones", ID_APP_CHECK, BS_SECONDARY, !g.appBusy);
    bx += S(222);
    if (g.appInfo.available) {
        drawButton(hdc, R(bx, by, bx + S(270), by + S(40)), L"Descargar e instalar " + W(g.appInfo.latestVersion), ID_APP_INSTALL, BS_PRIMARY,
                   !g.appBusy && !g.appInfo.installerUrl.empty());
        bx += S(282);
        if (!g.appInfo.pageUrl.empty()) drawButton(hdc, R(bx, by, bx + S(170), by + S(40)), L"Ver novedades", ID_APP_PAGE, BS_SECONDARY);
    }

    text(hdc, L"Las comprobaciones solo envian peticiones GET por HTTPS a GitHub; no se transmite informacion de su equipo. "
              L"El instalador descargado se verifica con su hash SHA-256 antes de ejecutarse.",
         R(body.left, app.bottom + S(10), body.right, body.bottom + S(30)), g.fSmall, C_MUTED);
}

void paintThreats(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Amenazas", L"Elija que hacer con cada amenaza detectada, una por una o varias a la vez");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);
    if (g.pending.empty()) {
        RECT box = R(body.left, body.top, body.right, body.top + S(120));
        drawCard(hdc, box);
        text(hdc, L"No hay amenazas pendientes", R(box.left + S(24), box.top + S(18), box.right - S(24), box.top + S(48)), g.fH2, C_OK, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, L"Las amenazas detectadas en los analisis aparecen aqui hasta que las aisle, elimine o ignore.",
             R(box.left + S(24), box.top + S(54), box.right - S(24), box.bottom - S(10)), g.fBody, C_MUTED);
    } else {
        text(hdc, std::to_wstring(g.pending.size()) + L" amenaza(s) pendiente(s). Use Ctrl o Mayus para elegir varias.",
             R(body.left, body.top - S(4), body.right, body.top + S(18)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    }
    const bool any = !g.pending.empty();
    int x = body.left;
    auto btn = [&](int width, const wchar_t* label, int id, BtnStyle style) {
        drawButton(hdc, R(x, by, x + S(width), by + S(40)), label, id, style, any);
        x += S(width) + S(12);
    };
    btn(210, L"Aislar seleccionadas", ID_THREAT_ISOLATE, BS_PRIMARY);
    btn(140, L"Eliminar", ID_THREAT_DELETE, BS_DANGER);
    btn(130, L"Ignorar", ID_THREAT_IGNORE, BS_SECONDARY);
    btn(170, L"Abrir ubicacion", ID_THREAT_OPEN, BS_SECONDARY);
    btn(170, L"Seleccionar todo", ID_THREAT_ALL, BS_SECONDARY);
}

void paintCleaner(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Limpieza", L"Libere espacio eliminando archivos temporales y caches que no necesita");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);
    const int rowH = S(66);
    const int n = static_cast<int>(g.clean.size());

    RECT card = R(body.left, body.top, body.right, body.top + rowH * std::max(n, 1) + S(8));
    drawCard(hdc, card);
    int y = card.top + S(4);
    uint64_t selBytes = 0;
    for (int i = 0; i < n; ++i) {
        const auto& r = g.clean[static_cast<size_t>(i)];
        text(hdc, r.cat.name, R(card.left + S(22), y + S(8), card.right - S(340), y + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, r.cat.description, R(card.left + S(22), y + S(30), card.right - S(340), y + rowH - S(2)), g.fSmall, C_MUTED);
        const std::wstring size = r.measured ? openguard::cleaner::formatBytes(r.usage.bytes) + L"  (" + std::to_wstring(r.usage.files) + L" archivos)"
                                             : std::wstring(L"Calculando...");
        text(hdc, size, R(card.right - S(330), y + S(8), card.right - S(96), y + S(32)), g.fBold, r.measured ? C_ACCENT : C_MUTED, DT_RIGHT | DT_SINGLELINE | DT_NOPREFIX);
        drawToggle(hdc, card.right - S(76), y + (rowH - S(24)) / 2, r.selected, TOG_CLEAN_BASE + i);
        if (r.selected && r.measured) selBytes += r.usage.bytes;
        y += rowH;
        fillRect(hdc, R(card.left + S(20), y - 1, card.right - S(20), y), C_BORDER);
    }
    if (n == 0) {
        text(hdc, L"No se encontraron carpetas que limpiar.", R(card.left + S(22), card.top + S(20), card.right - S(22), card.top + S(50)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    }

    text(hdc, L"Espacio que se liberara: " + openguard::cleaner::formatBytes(selBytes), R(body.left, card.bottom + S(12), body.right, card.bottom + S(38)),
         g.fH2, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    if (!g.cleanMsg.empty()) {
        text(hdc, g.cleanMsg, R(body.left, card.bottom + S(42), body.right, card.bottom + S(68)), g.fBody, g.cleanMsgOk ? C_OK : C_BAD, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    }
    text(hdc, L"OpenGuard no toca documentos, descargas ni programas. Solo temporales y caches que Windows y las aplicaciones vuelven a crear.",
         R(body.left, by - S(34), body.right, by - S(10)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    drawButton(hdc, R(body.left, by, body.left + S(230), by + S(40)), g.cleanBusy ? L"Espere..." : L"Limpiar seleccionado", ID_CLEAN_RUN, BS_PRIMARY, !g.cleanBusy && n > 0);
    drawButton(hdc, R(body.left + S(242), by, body.left + S(242) + S(190), by + S(40)), L"Analizar de nuevo", ID_CLEAN_ANALYZE, BS_SECONDARY, !g.cleanBusy);
}

void paintQuarantine(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Cuarentena", L"Archivos aislados en la boveda cifrada (AES-256)");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);
    drawButton(hdc, R(body.left, by, body.left + S(150), by + S(40)), L"Restaurar", ID_Q_RESTORE, BS_SECONDARY);
    drawButton(hdc, R(body.left + S(162), by, body.left + S(162) + S(230), by + S(40)), L"Eliminar definitivamente", ID_Q_DELETE, BS_DANGER);
    drawButton(hdc, R(body.left + S(404), by, body.left + S(404) + S(150), by + S(40)), L"Actualizar", ID_Q_REFRESH, BS_SECONDARY);
}

void paintReports(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Informes", L"Eventos de la proteccion en tiempo real");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);
    drawButton(hdc, R(body.left, by, body.left + S(220), by + S(40)), L"Abrir registro completo", ID_LOG_OPEN, BS_SECONDARY);
    drawButton(hdc, R(body.left + S(232), by, body.left + S(232) + S(150), by + S(40)), L"Actualizar", ID_LOG_REFRESH, BS_SECONDARY);
}

void paintSettings(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Configuracion", L"Personalice el comportamiento de la proteccion");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);
    const RECT view = R(body.left, body.top, body.right, by - S(12));

    struct Row { const wchar_t* title; const wchar_t* desc; bool* value; int id; };
    Row rows[] = {
        {L"Analizar archivos descargados", L"Analiza cada archivo nuevo de Descargas al terminar de bajar y lo aisla si es una amenaza confirmada.", &g.settings.scanDownloads, TOG_DOWNLOADS},
        {L"Archivos senuelo anti-ransomware", L"Crea archivos ocultos en Documentos y Escritorio y alerta si los modifican.", &g.settings.decoys, TOG_DECOY},
        {L"Ejecutar en segundo plano al cerrar la ventana", L"OpenGuard sigue en la bandeja del sistema avisando de amenazas y unidades nuevas (recomendado).", &g.settings.closeToTray, TOG_TRAY},
        {L"Iniciar con Windows en segundo plano", L"Abre OpenGuard al iniciar sesion, sin ventana y con su icono en la bandeja.", &g.settings.autostart, TOG_AUTOSTART},
        {L"Mostrar notificaciones en la bandeja", L"Avisa cuando se detecta o aisla una amenaza.", &g.settings.notify, TOG_NOTIFY},
        {L"Buscar actualizaciones del programa", L"Comprueba en GitHub si hay una version nueva de OpenGuard al abrir la aplicacion.", &g.settings.checkAppUpdates, TOG_APPUPD},
    };
    constexpr int kToggleRows = 6;
    const int rowH = S(60);
    const int totalRows = kToggleRows + 3; // + accion ante amenazas + unidades externas + CPU
    const int contentH = rowH * totalRows + S(8) + S(14) + S(72);

    const int viewH = view.bottom - view.top;
    g.settingsMaxScroll = std::max(0, contentH - viewH);
    g.settingsScroll = std::clamp(g.settingsScroll, 0, g.settingsMaxScroll);

    // Zona desplazable: todo lo que se dibuja aquí se recorta a la vista (GDI y GDI+)
    const ClipState clip = beginClip(hdc, view);
    g.clipOn = true;
    g.clipRect = view;

    const int top = view.top - g.settingsScroll;
    RECT card = R(body.left, top, body.right - (g.settingsMaxScroll > 0 ? S(14) : 0), top + rowH * totalRows + S(8));
    drawCard(hdc, card);
    int y = card.top + S(4);

    for (const auto& r : rows) {
        text(hdc, r.title, R(card.left + S(22), y + S(8), card.right - S(100), y + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, r.desc, R(card.left + S(22), y + S(30), card.right - S(100), y + rowH - S(2)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        drawToggle(hdc, card.right - S(76), y + (rowH - S(24)) / 2, *r.value, r.id);
        y += rowH;
        fillRect(hdc, R(card.left + S(20), y - 1, card.right - S(20), y), C_BORDER);
    }

    // Accion ante una amenaza: preguntar / aislar automaticamente / solo avisar
    {
        text(hdc, L"Que hacer ante una amenaza", R(card.left + S(22), y + S(8), card.right - S(250), y + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        const wchar_t* desc = g.prot.threatAction == "quarantine" ? L"Se aislan solas en cuarentena (analisis, tiempo real y descargas). Se pueden restaurar."
                            : g.prot.threatAction == "report"     ? L"Solo se registran y avisan; no se modifica ningun archivo."
                                                                  : L"Se listan en Amenazas y usted decide: aislar, eliminar o ignorar, una por una o varias a la vez.";
        text(hdc, desc, R(card.left + S(22), y + S(30), card.right - S(250), y + rowH - S(2)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        const wchar_t* label = g.prot.threatAction == "quarantine" ? L"Aislar solas" : g.prot.threatAction == "report" ? L"Solo avisar" : L"Preguntarme";
        drawButton(hdc, R(card.right - S(190), y + S(10), card.right - S(20), y + S(10) + S(38)), label, ID_THREAT_MODE, BS_SECONDARY);
        y += rowH;
        fillRect(hdc, R(card.left + S(20), y - 1, card.right - S(20), y), C_BORDER);
    }

    // Unidades externas: preguntar / automático / desactivado
    {
        text(hdc, L"Unidades externas (USB, tarjetas, discos)", R(card.left + S(22), y + S(8), card.right - S(250), y + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        const wchar_t* desc = g.prot.usbMode == "auto" ? L"Se analizan automaticamente al conectarlas."
                            : g.prot.usbMode == "off"  ? L"No se analizan (no recomendado)."
                                                       : L"Al conectarlas, OpenGuard pregunta si permite el analisis y ofrece reparar la unidad.";
        text(hdc, desc, R(card.left + S(22), y + S(30), card.right - S(250), y + rowH - S(2)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        const wchar_t* label = g.prot.usbMode == "auto" ? L"Automatico" : g.prot.usbMode == "off" ? L"Desactivado" : L"Preguntar";
        drawButton(hdc, R(card.right - S(190), y + S(10), card.right - S(20), y + S(10) + S(38)), label, ID_USB_MODE, BS_SECONDARY);
        y += rowH;
        fillRect(hdc, R(card.left + S(20), y - 1, card.right - S(20), y), C_BORDER);
    }

    // Límite de CPU de los análisis
    text(hdc, L"Uso maximo de CPU en los analisis", R(card.left + S(22), y + S(8), card.right - S(270), y + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"Menos CPU: analisis mas lentos pero un equipo mas fluido.", R(card.left + S(22), y + S(30), card.right - S(270), y + rowH - S(2)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    const int cpuIds[4] = {ID_CPU_25, ID_CPU_50, ID_CPU_75, ID_CPU_100};
    const int cpuVals[4] = {25, 50, 75, 100};
    int bx = card.right - S(256);
    for (int i = 0; i < 4; ++i) {
        const bool selected = (g.prot.cpuPercent == cpuVals[i]);
        drawButton(hdc, R(bx, y + S(10), bx + S(56), y + S(10) + S(34)), std::to_wstring(cpuVals[i]) + L"%", cpuIds[i], selected ? BS_PRIMARY : BS_SECONDARY);
        bx += S(62);
    }

    // Protección en tiempo real (servicio)
    const int py = card.bottom + S(14);
    RECT pc = R(body.left, py, card.right, py + S(72));
    drawCard(hdc, pc);
    const bool running = (g.svc == Svc::Running);
    text(hdc, L"Proteccion en tiempo real", R(pc.left + S(22), pc.top + S(10), pc.right - S(260), pc.top + S(34)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, running ? L"El servicio esta en ejecucion." : (g.svc == Svc::NotInstalled ? L"El servicio no esta instalado." : L"El servicio esta detenido."),
         R(pc.left + S(22), pc.top + S(36), pc.right - S(260), pc.top + S(60)), g.fSmall, running ? C_OK : C_BAD, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    drawButton(hdc, R(pc.right - S(236), pc.top + S(16), pc.right - S(20), pc.top + S(56)),
               running ? L"Desactivar proteccion" : L"Activar proteccion", ID_TOGGLE_PROTECTION, running ? BS_SECONDARY : BS_PRIMARY);

    // Indicador de desplazamiento
    g.clipOn = false;
    endClip(hdc, clip);
    if (g.settingsMaxScroll > 0) {
        const int trackH = viewH;
        const int thumbH = std::max(S(40), trackH * viewH / contentH);
        const int thumbY = view.top + (trackH - thumbH) * g.settingsScroll / g.settingsMaxScroll;
        roundRect(hdc, R(body.right - S(6), thumbY, body.right - S(2), thumbY + thumbH), S(4), C_BORDER, C_BORDER, false);
    }

    drawButton(hdc, R(body.left, by, body.left + S(190), by + S(40)), L"Guardar y aplicar", ID_SAVE_SETTINGS, BS_PRIMARY);
    drawButton(hdc, R(body.left + S(202), by, body.left + S(202) + S(210), by + S(40)),
               L"Exclusiones (" + std::to_wstring(g.prot.exclusions.size()) + L")...", ID_EXCL_OPEN, BS_SECONDARY);
    drawButton(hdc, R(body.left + S(424), by, body.left + S(424) + S(210), by + S(40)),
               g.prot.schedule.enabled ? L"Programacion (activa)..." : L"Programacion...", ID_SCHED_OPEN, BS_SECONDARY);
}

/// Texto "Próximo análisis" / "Último análisis programado" para la pantalla de programación e Inicio.
std::wstring scheduleSummary() {
    const auto& s = g.prot.schedule;
    if (!s.enabled) return L"Desactivado";
    static const wchar_t* kDays[7] = {L"domingo", L"lunes", L"martes", L"miercoles", L"jueves", L"viernes", L"sabado"};
    wchar_t hm[8];
    swprintf(hm, std::size(hm), L"%02d:%02d", s.hour, s.minute);
    std::wstring when = (s.frequency == "weekly") ? std::wstring(L"cada ") + kDays[s.weekday % 7] : std::wstring(L"todos los dias");
    const std::time_t next = openguard::scheduleNextRun(s, std::time(nullptr));
    const std::string nextText = openguard::formatLocalStamp(next);
    return std::wstring(s.type == "full" ? L"Completo, " : L"Rapido, ") + when + L" a las " + hm +
           (nextText.empty() ? L"" : L" (proximo: " + W(nextText.substr(0, 16)) + L")");
}

void paintSchedule(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Programacion de analisis", L"Ejecute analisis automaticos aunque no tenga abierta la aplicacion (los realiza el servicio)");
    const RECT body = bodyRect(w, h);
    auto& s = g.prot.schedule;

    const int rowH = S(60);
    RECT card = R(body.left, body.top, body.right, body.top + rowH * 5 + S(8));
    drawCard(hdc, card);
    int y = card.top + S(4);
    const int right = card.right - S(20);

    auto label = [&](int rowY, const wchar_t* title, const wchar_t* desc) {
        text(hdc, title, R(card.left + S(22), rowY + S(8), card.left + S(330), rowY + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, desc, R(card.left + S(22), rowY + S(30), card.left + S(330), rowY + rowH - S(2)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    };
    auto sep = [&](int rowY) { fillRect(hdc, R(card.left + S(20), rowY - 1, card.right - S(20), rowY), C_BORDER); };

    // 1. Activar
    label(y, L"Analisis programado", L"Activa o desactiva la programacion.");
    drawToggle(hdc, right - S(46), y + (rowH - S(24)) / 2, s.enabled, TOG_SCHED);
    y += rowH; sep(y);

    // 2. Tipo
    label(y, L"Tipo de analisis", L"Rapido: zonas de riesgo. Completo: todas las unidades.");
    drawButton(hdc, R(right - S(230), y + S(10), right - S(120), y + S(10) + S(38)), L"Rapido", ID_SCHED_QUICK, s.type == "quick" ? BS_PRIMARY : BS_SECONDARY);
    drawButton(hdc, R(right - S(110), y + S(10), right, y + S(10) + S(38)), L"Completo", ID_SCHED_FULL, s.type == "full" ? BS_PRIMARY : BS_SECONDARY);
    y += rowH; sep(y);

    // 3. Frecuencia
    label(y, L"Frecuencia", L"Con que periodicidad se ejecuta.");
    drawButton(hdc, R(right - S(230), y + S(10), right - S(120), y + S(10) + S(38)), L"Diario", ID_SCHED_DAILY, s.frequency == "daily" ? BS_PRIMARY : BS_SECONDARY);
    drawButton(hdc, R(right - S(110), y + S(10), right, y + S(10) + S(38)), L"Semanal", ID_SCHED_WEEKLY, s.frequency == "weekly" ? BS_PRIMARY : BS_SECONDARY);
    y += rowH; sep(y);

    // 4. Hora
    label(y, L"Hora", L"Hora local. Si el equipo esta apagado, se ejecuta al encenderlo.");
    wchar_t hh[8], mm[8];
    swprintf(hh, std::size(hh), L"%02d", s.hour);
    swprintf(mm, std::size(mm), L"%02d", s.minute);
    int bx = right - S(300);
    drawButton(hdc, R(bx, y + S(10), bx + S(38), y + S(48)), L"-", ID_SCHED_HOUR_DOWN, BS_SECONDARY);
    text(hdc, hh, R(bx + S(40), y + S(10), bx + S(82), y + S(48)), g.fH2, C_TEXT, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    drawButton(hdc, R(bx + S(84), y + S(10), bx + S(122), y + S(48)), L"+", ID_SCHED_HOUR_UP, BS_SECONDARY);
    text(hdc, L":", R(bx + S(124), y + S(10), bx + S(140), y + S(48)), g.fH2, C_TEXT, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    drawButton(hdc, R(bx + S(142), y + S(10), bx + S(180), y + S(48)), L"-", ID_SCHED_MIN_DOWN, BS_SECONDARY);
    text(hdc, mm, R(bx + S(182), y + S(10), bx + S(224), y + S(48)), g.fH2, C_TEXT, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    drawButton(hdc, R(bx + S(226), y + S(10), bx + S(264), y + S(48)), L"+", ID_SCHED_MIN_UP, BS_SECONDARY);
    y += rowH; sep(y);

    // 5. Dia (solo semanal)
    static const wchar_t* kDays[7] = {L"Domingo", L"Lunes", L"Martes", L"Miercoles", L"Jueves", L"Viernes", L"Sabado"};
    label(y, L"Dia de la semana", L"Solo para la frecuencia semanal (pulse para cambiar).");
    drawButton(hdc, R(right - S(200), y + S(10), right, y + S(10) + S(38)), kDays[s.weekday % 7], ID_SCHED_DAY_NEXT, BS_SECONDARY, s.frequency == "weekly");

    // Resumen
    const std::wstring last = iniGetStr(openguard::paths::dataDir() / L"status.ini", L"schedule", L"last_run", L"Nunca");
    text(hdc, L"Programacion: " + scheduleSummary(), R(body.left, card.bottom + S(16), body.right, card.bottom + S(40)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"Ultima ejecucion programada: " + last, R(body.left, card.bottom + S(42), body.right, card.bottom + S(66)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    const int by = bottomButtonsTop(h);
    drawButton(hdc, R(body.left, by, body.left + S(220), by + S(40)), L"Guardar y aplicar", ID_SCHED_SAVE, BS_PRIMARY);
    drawButton(hdc, R(body.left + S(232), by, body.left + S(232) + S(140), by + S(40)), L"Volver", ID_SCHED_BACK, BS_SECONDARY);
}

void paintFeeds(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Fuentes de firmas", L"Actualizacion automatica con verificacion criptografica de lo descargado");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);

    const int rowH = S(60);
    RECT card = R(body.left, body.top, body.right, body.top + rowH * 5 + S(8));
    drawCard(hdc, card);
    int y = card.top + S(4);
    const int right = card.right - S(20);

    auto label = [&](int rowY, const wchar_t* title, const wchar_t* desc) {
        text(hdc, title, R(card.left + S(22), rowY + S(8), card.right - S(260), rowY + S(30)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, desc, R(card.left + S(22), rowY + S(30), card.right - S(260), rowY + rowH - S(2)), g.fSmall, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    };
    auto sep = [&](int rowY) { fillRect(hdc, R(card.left + S(20), rowY - 1, card.right - S(20), rowY), C_BORDER); };

    label(y, L"Actualizacion automatica", L"El servicio comprueba las fuentes sin que usted haga nada.");
    drawToggle(hdc, right - S(46), y + (rowH - S(24)) / 2, g.prot.autoUpdate, TOG_AUTOUPD);
    y += rowH; sep(y);

    label(y, L"Frecuencia", L"Cada cuanto tiempo se comprueban las fuentes.");
    drawButton(hdc, R(right - S(190), y + S(10), right, y + S(10) + S(38)), L"Cada " + std::to_wstring(g.prot.updateHours) + (g.prot.updateHours == 1 ? L" hora" : L" horas"), ID_FEED_HOURS, BS_SECONDARY);
    y += rowH; sep(y);

    label(y, L"Reglas YARA oficiales (firmadas)", L"Se verifica la firma ECDSA del manifiesto y el hash de cada regla.");
    drawToggle(hdc, right - S(46), y + (rowH - S(24)) / 2, g.prot.feedRules, TOG_FEEDRULES);
    y += rowH; sep(y);

    label(y, L"MalwareBazaar (abuse.ch)", L"Hashes de malware reciente. Requiere una clave gratuita de abuse.ch.");
    drawToggle(hdc, right - S(46), y + (rowH - S(24)) / 2, g.prot.feedBazaar, TOG_BAZAAR);
    y += rowH; sep(y);

    const bool hasKey = openguard::SecretStore().has(openguard::kAbuseChSecret);
    label(y, L"Clave de abuse.ch", hasKey ? L"Guardada y cifrada con DPAPI (no se muestra)." : L"No configurada. Copie su Auth-Key y pulse \"Pegar\".");
    drawButton(hdc, R(right - S(250), y + S(10), right - S(110), y + S(10) + S(38)), L"Pegar", ID_FEED_KEY_PASTE, BS_PRIMARY);
    drawButton(hdc, R(right - S(100), y + S(10), right, y + S(10) + S(38)), L"Quitar", ID_FEED_KEY_REMOVE, BS_SECONDARY, hasKey);

    const std::wstring last = iniGetStr(openguard::paths::dataDir() / L"status.ini", L"feeds", L"last_run", L"Nunca");
    text(hdc, L"Ultima comprobacion automatica: " + last, R(body.left, card.bottom + S(14), body.right, card.bottom + S(38)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    if (!g.feedMsg.empty()) {
        text(hdc, g.feedMsg, R(body.left, card.bottom + S(42), body.right, by - S(10)), g.fBody, g.feedOk ? C_OK : C_WARN);
    }

    drawButton(hdc, R(body.left, by, body.left + S(200), by + S(40)), L"Guardar y aplicar", ID_FEEDS_SAVE, BS_PRIMARY);
    drawButton(hdc, R(body.left + S(212), by, body.left + S(212) + S(200), by + S(40)), g.feedBusy ? L"Actualizando..." : L"Actualizar ahora", ID_FEEDS_RUN, BS_SECONDARY, !g.feedBusy);
    drawButton(hdc, R(body.left + S(424), by, body.left + S(424) + S(130), by + S(40)), L"Volver", ID_FEEDS_BACK, BS_SECONDARY);
}

void paintExclusions(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Exclusiones", L"Carpetas y archivos que OpenGuard no analizara (use con precaucion)");
    const RECT body = bodyRect(w, h);
    const int by = bottomButtonsTop(h);
    drawButton(hdc, R(body.left, by, body.left + S(190), by + S(40)), L"Agregar carpeta...", ID_EXCL_ADD_DIR, BS_PRIMARY);
    drawButton(hdc, R(body.left + S(202), by, body.left + S(202) + S(190), by + S(40)), L"Agregar archivo...", ID_EXCL_ADD_FILE, BS_SECONDARY);
    drawButton(hdc, R(body.left + S(404), by, body.left + S(404) + S(180), by + S(40)), L"Quitar seleccionada", ID_EXCL_REMOVE, BS_DANGER);
    drawButton(hdc, R(body.right - S(140), by, body.right, by + S(40)), L"Volver", ID_EXCL_BACK, BS_SECONDARY);
}

/// Notificaciones flotantes (esquina inferior derecha).
void paintToasts(HDC hdc, int w, int h) {
    const ULONGLONG now = GetTickCount64();
    g.toasts.erase(std::remove_if(g.toasts.begin(), g.toasts.end(), [now](const Toast& t) { return t.expire <= now; }), g.toasts.end());

    int y = h - S(28);
    for (auto it = g.toasts.rbegin(); it != g.toasts.rend(); ++it) {
        const int tw = S(340), th = S(58);
        const RECT rc = R(w - S(28) - tw, y - th, w - S(28), y);
        glowRound(rc, S(14), it->color, 3, 70);
        glassPanel(rc, S(14), it->color, 200);
        Gdiplus::SolidBrush bar(gc(it->color));
        g.gfx->FillRectangle(&bar, static_cast<int>(rc.left) + S(1), static_cast<int>(rc.top) + S(12), S(4), th - S(24));
        text(hdc, it->text, R(rc.left + S(18), rc.top + S(6), rc.right - S(14), rc.bottom - S(6)), g.fBody, C_TEXT, DT_LEFT | DT_VCENTER | DT_WORDBREAK | DT_NOPREFIX | DT_END_ELLIPSIS);
        y -= th + S(10);
    }
}

void paintAll(HDC hdc, int w, int h) {
    g.hits.clear();
    SetRectEmpty(&g.animRect);
    SetBkMode(hdc, TRANSPARENT);
    fillRect(hdc, R(0, 0, w, h), C_BG);
    paintSidebar(hdc, h);
    switch (g.page) {
        case PG_HOME:       paintHome(hdc, w, h); break;
        case PG_SCAN:       paintScan(hdc, w, h); break;
        case PG_THREATS:    paintThreats(hdc, w, h); break;
        case PG_CLEANER:    paintCleaner(hdc, w, h); break;
        case PG_UPDATE:     paintUpdate(hdc, w, h); break;
        case PG_QUARANTINE: paintQuarantine(hdc, w, h); break;
        case PG_REPORTS:    paintReports(hdc, w, h); break;
        case PG_SETTINGS:   paintSettings(hdc, w, h); break;
        case PG_EXCLUSIONS: paintExclusions(hdc, w, h); break;
        case PG_SCHEDULE:   paintSchedule(hdc, w, h); break;
        case PG_FEEDS:      paintFeeds(hdc, w, h); break;
        default: break;
    }
    paintToasts(hdc, w, h);
}

void restartProtectionIfRunning() {
    if (queryService() != Svc::Running) return;
    std::wstring err;
    setProtection(false, err);
    setProtection(true, err);
    refreshData();
}

void onHit(int id) {
    if (id >= NAV_BASE && id < static_cast<int>(NAV_BASE) + static_cast<int>(PG_COUNT)) { showPage(static_cast<Page>(id - NAV_BASE)); return; }

    if (id >= TOG_CLEAN_BASE && id < TOG_CLEAN_BASE + 16) {
        const size_t i = static_cast<size_t>(id - TOG_CLEAN_BASE);
        if (i < g.clean.size()) g.clean[i].selected = !g.clean[i].selected;
        InvalidateRect(g.main, nullptr, FALSE);
        return;
    }

    switch (id) {
        case ID_CLEAN_ANALYZE: startCleanAnalysis(true); break;
        case ID_CLEAN_RUN: startClean(); break;
        case ID_SCAN_QUICK: startScan(quickTargets(), openguard::ScanType::Quick); break;
        case ID_SCAN_FULL:
            if (MessageBoxW(g.main, L"El analisis completo recorre todas las unidades y puede tardar bastante. Continuar?",
                            L"Analisis completo", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                startScan(openguard::FileScanner::getFixedDrives(), openguard::ScanType::Full);
            }
            break;
        case ID_SCAN_FOLDER: chooseFolderAndScan(); break;
        case ID_CANCEL: {
            std::lock_guard<std::mutex> lock(g.scannerMutex);
            if (g.scanner) g.scanner->cancelScan();
            g.scanStatus = L"Cancelando...";
            break;
        }
        case ID_ISOLATE: isolateSelected(); break;
        case ID_THREAT_ISOLATE: pendingAction(ThreatOp::Isolate); break;
        case ID_THREAT_DELETE: pendingAction(ThreatOp::Delete); break;
        case ID_THREAT_IGNORE: pendingAction(ThreatOp::Ignore); break;
        case ID_THREAT_OPEN: openPendingLocation(); break;
        case ID_THREAT_ALL: selectAllRows(); break;
        case ID_THREAT_MODE:
            g.prot.threatAction = (g.prot.threatAction == "ask") ? "quarantine" : (g.prot.threatAction == "quarantine") ? "report" : "ask";
            break;
        case ID_UPDATE_NOW: startUpdate(); break;
        case ID_FIX: showPage(PG_UPDATE); startUpdate(); break;
        case ID_IMPORT_FILE: importFromFile(); break;
        case ID_Q_RESTORE: quarantineAction(true); break;
        case ID_Q_DELETE: quarantineAction(false); break;
        case ID_Q_REFRESH: fillQuarantineList(); break;
        case ID_LOG_OPEN: openLog(); break;
        case ID_LOG_REFRESH: fillReportList(); break;
        case ID_TOGGLE_PROTECTION: {
            std::wstring err;
            const bool enable = (g.svc != Svc::Running);
            if (!setProtection(enable, err)) {
                MessageBoxW(g.main, err.c_str(), L"OpenGuard", MB_OK | MB_ICONWARNING);
            }
            Sleep(300);
            refreshData();
            break;
        }
        case TOG_DECOY: g.settings.decoys = !g.settings.decoys; break;
        case TOG_USB: g.settings.scanUsb = !g.settings.scanUsb; break;
        case TOG_NOTIFY: g.settings.notify = !g.settings.notify; break;
        case TOG_DOWNLOADS: g.settings.scanDownloads = !g.settings.scanDownloads; break;
        case TOG_TRAY: g.settings.closeToTray = !g.settings.closeToTray; break;
        case TOG_AUTOSTART: g.settings.autostart = !g.settings.autostart; break;
        case ID_USB_MODE:
            g.prot.usbMode = (g.prot.usbMode == "ask") ? "auto" : (g.prot.usbMode == "auto") ? "off" : "ask";
            break;
        case TOG_APPUPD: g.settings.checkAppUpdates = !g.settings.checkAppUpdates; break;
        case ID_CPU_25: g.prot.cpuPercent = 25; break;
        case ID_CPU_50: g.prot.cpuPercent = 50; break;
        case ID_CPU_75: g.prot.cpuPercent = 75; break;
        case ID_CPU_100: g.prot.cpuPercent = 100; break;
        case ID_EXCL_OPEN: showPage(PG_EXCLUSIONS); break;
        case ID_EXCL_BACK: showPage(PG_SETTINGS); break;
        case ID_SCHED_OPEN: showPage(PG_SCHEDULE); break;
        case ID_FEEDS_OPEN: showPage(PG_FEEDS); break;
        case ID_FEEDS_BACK: showPage(PG_UPDATE); break;
        case TOG_AUTOUPD: g.prot.autoUpdate = !g.prot.autoUpdate; break;
        case TOG_FEEDRULES: g.prot.feedRules = !g.prot.feedRules; break;
        case TOG_BAZAAR: g.prot.feedBazaar = !g.prot.feedBazaar; break;
        case ID_FEED_HOURS: {
            static const int kHours[] = {1, 6, 12, 24, 72, 168};
            int next = kHours[0];
            for (size_t i = 0; i < std::size(kHours); ++i) {
                if (g.prot.updateHours == kHours[i]) { next = kHours[(i + 1) % std::size(kHours)]; break; }
            }
            g.prot.updateHours = next;
            break;
        }
        case ID_FEED_KEY_PASTE: pasteFeedKeyFromClipboard(); break;
        case ID_FEED_KEY_REMOVE:
            if (MessageBoxW(g.main, L"Se eliminara la clave de abuse.ch guardada. Continuar?", L"Clave de abuse.ch", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                openguard::SecretStore().remove(openguard::kAbuseChSecret);
            }
            break;
        case ID_FEEDS_RUN: startFeedUpdate(); break;
        case ID_FEEDS_SAVE:
            if (!g.prot.save()) {
                MessageBoxW(g.main, L"No se pudo guardar (ejecute OpenGuard como Administrador).", L"OpenGuard", MB_OK | MB_ICONWARNING);
            } else {
                restartProtectionIfRunning();
                pushToast(L"Configuracion de fuentes guardada", C_OK);
            }
            break;

        case ID_SCHED_BACK: showPage(PG_SETTINGS); break;
        case TOG_SCHED: g.prot.schedule.enabled = !g.prot.schedule.enabled; break;
        case ID_SCHED_QUICK: g.prot.schedule.type = "quick"; break;
        case ID_SCHED_FULL: g.prot.schedule.type = "full"; break;
        case ID_SCHED_DAILY: g.prot.schedule.frequency = "daily"; break;
        case ID_SCHED_WEEKLY: g.prot.schedule.frequency = "weekly"; break;
        case ID_SCHED_HOUR_UP: g.prot.schedule.hour = (g.prot.schedule.hour + 1) % 24; break;
        case ID_SCHED_HOUR_DOWN: g.prot.schedule.hour = (g.prot.schedule.hour + 23) % 24; break;
        case ID_SCHED_MIN_UP: g.prot.schedule.minute = (g.prot.schedule.minute + 5) % 60; break;
        case ID_SCHED_MIN_DOWN: g.prot.schedule.minute = (g.prot.schedule.minute + 55) % 60; break;
        case ID_SCHED_DAY_NEXT: g.prot.schedule.weekday = (g.prot.schedule.weekday + 1) % 7; break;
        case ID_SCHED_SAVE:
            if (!g.prot.save()) {
                MessageBoxW(g.main, L"No se pudo guardar la programacion (ejecute OpenGuard como Administrador).", L"OpenGuard", MB_OK | MB_ICONWARNING);
            } else {
                restartProtectionIfRunning();
                MessageBoxW(g.main, L"Programacion guardada. Se aplico reiniciando la proteccion.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
            }
            break;
        case ID_EXCL_ADD_DIR:
        case ID_EXCL_ADD_FILE: {
            fs::path chosen;
            if (id == ID_EXCL_ADD_DIR) {
                BROWSEINFOW bi{};
                bi.hwndOwner = g.main;
                bi.lpszTitle = L"Seleccione la carpeta a excluir";
                bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
                if (PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi)) {
                    wchar_t path[MAX_PATH]{};
                    if (SHGetPathFromIDListW(pidl, path)) chosen = path;
                    CoTaskMemFree(pidl);
                }
            } else {
                wchar_t file[MAX_PATH]{};
                OPENFILENAMEW ofn{};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = g.main;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                if (GetOpenFileNameW(&ofn)) chosen = file;
            }
            if (!chosen.empty()) {
                if (chosen.has_relative_path() == false || chosen == chosen.root_path()) {
                    MessageBoxW(g.main, L"No se puede excluir una unidad completa.", L"OpenGuard", MB_OK | MB_ICONWARNING);
                } else {
                    g.prot.exclusions.push_back(chosen);
                    if (!g.prot.save()) MessageBoxW(g.main, L"No se pudo guardar (ejecute OpenGuard como Administrador).", L"OpenGuard", MB_OK | MB_ICONWARNING);
                    else restartProtectionIfRunning();
                    fillExclusionList();
                }
            }
            break;
        }
        case ID_EXCL_REMOVE: {
            const auto rows = selectedRows();
            if (rows.empty()) { MessageBoxW(g.main, L"Seleccione una exclusion de la lista.", L"OpenGuard", MB_OK | MB_ICONINFORMATION); break; }
            for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
                if (static_cast<size_t>(*it) < g.prot.exclusions.size()) g.prot.exclusions.erase(g.prot.exclusions.begin() + *it);
            }
            if (g.prot.save()) restartProtectionIfRunning();
            fillExclusionList();
            break;
        }
        case ID_APP_CHECK: startAppCheck(false); break;
        case ID_APP_INSTALL: startAppInstall(); break;
        case ID_APP_PAGE:
            if (g.appInfo.pageUrl.rfind("https://", 0) == 0) ShellExecuteW(g.main, L"open", W(g.appInfo.pageUrl).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        case ID_SAVE_SETTINGS: {
            const bool downloadsWereOn = openguard::ProtectionSettings::load().scanDownloads;
            const bool autostartWasOn = isAutostartEnabled();
            if (g.settings.autostart != autostartWasOn && !setAutostart(g.settings.autostart)) {
                MessageBoxW(g.main, L"No se pudo cambiar el inicio automatico con Windows.", L"OpenGuard", MB_OK | MB_ICONWARNING);
                g.settings.autostart = autostartWasOn;
            }
            if (!saveSettings()) {
                MessageBoxW(g.main, L"No se pudo guardar la configuracion del servicio.", L"OpenGuard", MB_OK | MB_ICONWARNING);
            } else if (queryService() == Svc::Running) {
                restartProtectionIfRunning();
                MessageBoxW(g.main, L"Configuracion guardada. La proteccion se reinicio para aplicar los cambios.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(g.main, L"Configuracion guardada.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
            }
            // Al activar el analisis de descargas se revisa de inmediato lo que ya hay en la carpeta
            if (!downloadsWereOn && g.settings.scanDownloads && !g.scanning) {
                wchar_t prof[MAX_PATH * 2]{};
                if (GetEnvironmentVariableW(L"USERPROFILE", prof, static_cast<DWORD>(std::size(prof)))) {
                    startScan({fs::path(prof) / L"Downloads"}, openguard::ScanType::Custom);
                }
            }
            break;
        }
        default: break;
    }
    InvalidateRect(g.main, nullptr, FALSE);
}

int hitTest(int x, int y) {
    for (auto it = g.hits.rbegin(); it != g.hits.rend(); ++it) {
        if (x >= it->r.left && x < it->r.right && y >= it->r.top && y < it->r.bottom) return it->id;
    }
    return 0;
}

/// Menú contextual del icono de la bandeja.
void showTrayMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, L"Abrir OpenGuard");
    AppendMenuW(menu, MF_STRING, ID_TRAY_QUICK, L"Analisis rapido");
    AppendMenuW(menu, MF_STRING, ID_TRAY_TOGGLE, g.svc == Svc::Running ? L"Desactivar proteccion" : L"Activar proteccion");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Salir de OpenGuard");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g.main); // necesario para que el menú se cierre al pulsar fuera
    const int cmd = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, g.main, nullptr);
    DestroyMenu(menu);
    PostMessageW(g.main, WM_NULL, 0, 0);

    switch (cmd) {
        case ID_TRAY_OPEN: showMainWindow(); break;
        case ID_TRAY_QUICK:
            showMainWindow();
            startScan(quickTargets(), openguard::ScanType::Quick);
            break;
        case ID_TRAY_TOGGLE: onHit(ID_TOGGLE_PROTECTION); break;
        case ID_TRAY_EXIT:
            g.quitting = true;
            DestroyWindow(g.main);
            break;
        default: break;
    }
}

HFONT makeFont(int px, int weight, const wchar_t* face = L"Segoe UI") {
    return CreateFontW(-S(px), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g.main = hwnd;
            g.fH1 = makeFont(28, FW_SEMIBOLD, L"Bahnschrift"); // tipografía técnica de Windows 10/11
            g.fH2 = makeFont(17, FW_SEMIBOLD, L"Bahnschrift");
            g.fBig = makeFont(34, FW_SEMIBOLD, L"Bahnschrift");
            g.fBody = makeFont(14, FW_NORMAL);
            g.fBold = makeFont(14, FW_SEMIBOLD);
            g.fSmall = makeFont(12, FW_NORMAL);
            g.fIcon = makeFont(18, FW_NORMAL, L"Segoe MDL2 Assets");
            g.icon = static_cast<HICON>(LoadImageW(g.hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, S(48), S(48), LR_DEFAULTCOLOR));

            g.list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                                     WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                                     0, 0, 10, 10, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LIST)), g.hInst, nullptr);
            ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            SendMessageW(g.list, WM_SETFONT, reinterpret_cast<WPARAM>(g.fBody), TRUE);
            ListView_SetBkColor(g.list, C_CARD);
            ListView_SetTextBkColor(g.list, C_CARD);
            ListView_SetTextColor(g.list, C_TEXT);
            SetWindowTheme(g.list, L"DarkMode_Explorer", nullptr); // barras de desplazamiento y selección oscuras
            SetWindowTheme(ListView_GetHeader(g.list), L"DarkMode_ItemsView", nullptr);


            g.progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | PBS_MARQUEE, 0, 0, 10, 10, hwnd,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PROGRESS)), g.hInst, nullptr);

            SetWindowTheme(g.progress, L"", L""); // sin tema: permite colorear la barra
            SendMessageW(g.progress, PBM_SETBARCOLOR, 0, static_cast<LPARAM>(C_ACCENT));
            SendMessageW(g.progress, PBM_SETBKCOLOR, 0, static_cast<LPARAM>(RGB(30, 38, 58)));

            loadSettings();
            g.history = std::make_unique
<openguard::ThreatHistory>(openguard::paths::dataDir() / "history.db");
            refreshData();
            loadYaraCount();
            layoutControls();
            addTrayIcon();
            SetTimer(hwnd, TIMER_REFRESH, 5000, nullptr);
            SetTimer(hwnd, TIMER_LOGPOLL, 5000, nullptr);
            SetTimer(hwnd, TIMER_ANIM, 40, nullptr); // animación del anillo de estado (~25 fps)
            SetTimer(hwnd, TIMER_APPCHECK, 6 * 60 * 60 * 1000, nullptr); // revisa nuevas versiones cada 6 horas
            if (g.settings.checkAppUpdates) startAppCheck(true);
            return 0;
        }
        case WM_SIZE:
            layoutControls();
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            const int w = rc.right, h = rc.bottom;
            const RECT pr = ps.rcPaint;
            HDC mem = CreateCompatibleDC(hdc);
            HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
            HGDIOBJ old = SelectObject(mem, bmp);
            IntersectClipRect(mem, pr.left, pr.top, pr.right, pr.bottom); // la animación solo repinta su zona
            {
                Gdiplus::Graphics gfx(mem);
                gfx.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
                gfx.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHalf);
                gfx.SetClip(Gdiplus::Rect(pr.left, pr.top, pr.right - pr.left, pr.bottom - pr.top));
                g.gfx = &gfx;
                paintAll(mem, w, h);
                gfx.Flush(Gdiplus::FlushIntentionSync);
                g.gfx = nullptr;
            }
            BitBlt(hdc, pr.left, pr.top, pr.right - pr.left, pr.bottom - pr.top, mem, pr.left, pr.top, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = S(980);
            mmi->ptMinTrackSize.y = S(700);
            return 0;
        }
        case WM_MOUSEMOVE: {
            const int id = hitTest(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
            if (!g.tracking) {
                TRACKMOUSEEVENT tme{sizeof(tme), TME_LEAVE, hwnd, 0};
                TrackMouseEvent(&tme);
                g.tracking = true;
            }
            if (id != g.hover) { g.hover = id; InvalidateRect(hwnd, nullptr, FALSE); }
            return 0;
        }
        case WM_MOUSELEAVE:
            g.tracking = false;
            if (g.hover != 0) { g.hover = 0; InvalidateRect(hwnd, nullptr, FALSE); }
            return 0;
        case WM_SETCURSOR:
            if (LOWORD(lp) == HTCLIENT && g.hover != 0) { SetCursor(LoadCursorW(nullptr, IDC_HAND)); return TRUE; }
            break;
        case WM_LBUTTONUP: {
            const int id = hitTest(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
            if (id != 0) onHit(id);
            return 0;
        }
        case WM_TIMER:
            if (wp == TIMER_ANIM) {
                if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) return 0; // oculto en la bandeja: sin gasto de CPU
                g.animPhase += 0.012;
                if (g.animPhase >= 1.0) g.animPhase -= 1.0;
                if (!IsRectEmpty(&g.animRect)) InvalidateRect(hwnd, &g.animRect, FALSE);
                if (!g.toasts.empty()) InvalidateRect(hwnd, nullptr, FALSE);
                return 0;
            }
            if (wp == TIMER_LOGPOLL) { pollServiceLog(); return 0; }

            if (wp == TIMER_APPCHECK) { if (g.settings.checkAppUpdates) startAppCheck(true); return 0; }
            if (wp == TIMER_REFRESH && !g.scanning) { refreshData(); InvalidateRect(hwnd, nullptr, FALSE); }
            return 0;
        case WM_APP_PROGRESS: {
            const size_t processed = static_cast<size_t>(wp);
            const size_t total = static_cast<size_t>(lp);
            if (g.scanTotalKnown && total > 0) {
                setProgressMode(false);
                const size_t pos = std::min<size_t>(1000, processed * 1000 / total);
                SendMessageW(g.progress, PBM_SETPOS, static_cast<WPARAM>(pos), 0);
                g.scanStatus = L"Analizando... " + std::to_wstring(processed) + L" de " + std::to_wstring(total) +
                               L" archivos (" + std::to_wstring(pos / 10) + L"%)";
            } else {
                g.scanStatus = L"Analizando... " + std::to_wstring(processed) + L" archivos analizados (" +
                               std::to_wstring(total) + L" encontrados hasta ahora)";
            }
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        case WM_APP_DONE:
            onScanDone(reinterpret_cast<openguard::ScanSessionStats*>(lp));
            return 0;
        case WM_APP_APPCHECK_DONE:
            onAppCheckDone(reinterpret_cast<openguard::AppUpdateInfo*>(lp));
            return 0;
        case WM_APP_APPDL_DONE:
            onAppDownloadDone(reinterpret_cast<DownloadResult*>(lp));
            return 0;
        case WM_APP_CLEAN_DONE:
            onCleanDone(reinterpret_cast<CleanReport*>(lp));
            return 0;
        case WM_APP_FEEDS_DONE:
            onFeedsDone(reinterpret_cast<std::vector<openguard::FeedResult>*>(lp));
            return 0;
        case WM_APP_UPDATE_DONE:
            onUpdateDone(reinterpret_cast<openguard::UpdateResult*>(lp));
            return 0;
        case WM_APP_TRAY:
            if (LOWORD(lp) == WM_RBUTTONUP) {
                showTrayMenu();
            } else if (LOWORD(lp) == WM_LBUTTONUP || LOWORD(lp) == WM_LBUTTONDBLCLK || LOWORD(lp) == NIN_BALLOONUSERCLICK) {
                showMainWindow();
                if (LOWORD(lp) == NIN_BALLOONUSERCLICK) showPage(PG_REPORTS);
            }
            return 0;
        case WM_APP_SHOW: // otra instancia (o el inicio automático) pide mostrar la ventana
            showMainWindow();
            return 0;
        case WM_APP_USB:
            onVolumeArrived(static_cast<wchar_t>(wp));
            return 0;
        case WM_DEVICECHANGE:
            // Se conectó una unidad (USB, tarjeta, disco externo): se encola para no bloquear el sistema con un diálogo
            if (wp == DBT_DEVICEARRIVAL && lp != 0) {
                const auto* hdr = reinterpret_cast<const DEV_BROADCAST_HDR*>(lp);
                if (hdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                    const auto* vol = reinterpret_cast<const DEV_BROADCAST_VOLUME*>(lp);
                    for (int i = 0; i < 26; ++i) {
                        if (vol->dbcv_unitmask & (1u << i)) PostMessageW(hwnd, WM_APP_USB, static_cast<WPARAM>(L'A' + i), 0);
                    }
                }
            }
            return TRUE;
        case WM_MOUSEWHEEL:
            if (g.page == PG_SETTINGS && g.settingsMaxScroll > 0) {
                g.settingsScroll -= (GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA) * S(60);
                g.settingsScroll = std::clamp(g.settingsScroll, 0, g.settingsMaxScroll);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        case WM_CLOSE:
            // Segundo plano: cerrar la ventana solo la oculta; la protección y los avisos siguen en la bandeja
            if (g.settings.closeToTray && !g.quitting) {
                ShowWindow(hwnd, SW_HIDE);
                if (!g.trayHintShown) {
                    g.trayHintShown = true;
                    showBalloon(L"OpenGuard sigue protegiendo", L"Se ejecuta en segundo plano. Haga clic en el icono de la bandeja para abrirlo.", NIIF_INFO);
                }
                return 0;
            }
            if (g.scanning) {
                std::lock_guard<std::mutex> lock(g.scannerMutex);
                if (g.scanner) g.scanner->cancelScan();
            }
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            removeTrayIcon();
            if (g.worker.joinable()) g.worker.join();
            if (g.updater.joinable()) g.updater.join();
            if (g.appThread.joinable()) g.appThread.join();
            if (g.feedThread.joinable()) g.feedThread.join();
            g.cleanCancel = true;
            if (g.cleanThread.joinable()) g.cleanThread.join();
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

} // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    OleInitialize(nullptr);
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    Gdiplus::GdiplusStartupInput gdiplusInput;
    Gdiplus::GdiplusStartup(&g.gdiplusToken, &gdiplusInput, nullptr);

    // Instancia única: el servicio también usa este objeto para saber si la aplicación está abierta (preguntará ella
    // al conectar una unidad). Si ya hay otra, se le pide que muestre su ventana y esta termina.
    g.instanceMutex = CreateMutexW(nullptr, FALSE, L"Global\\OpenGuardGuiRunning");
    if (g.instanceMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        if (HWND other = FindWindowW(L"OpenGuardMainWindow", nullptr)) PostMessageW(other, WM_APP_SHOW, 0, 0);
        return 0;
    }
    const bool startHidden = (wcsstr(GetCommandLineW(), L"--tray") != nullptr); // inicio automático: solo el icono

    g.hInst = hInstance;
    HDC screen = GetDC(nullptr);
    g.scale = GetDeviceCaps(screen, LOGPIXELSX) / 96.0;
    ReleaseDC(nullptr, screen);

    g.db = std::make_shared<openguard::SignatureDB>(openguard::paths::databasePath());
    if (g.db->isOpen() && !g.db->isReadOnly()) {
        g.db->seedEicar();
        size_t ins = 0, skp = 0;
        g.db->importFromJson(openguard::paths::signaturesDir() / "hashes_index.json", ins, skp);
    }

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.hIconSm = wc.hIcon;
    wc.lpszClassName = L"OpenGuardMainWindow";
    RegisterClassExW(&wc);

    RECT client = R(0, 0, S(1100), S(720));
    const DWORD style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
    AdjustWindowRect(&client, style, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"OpenGuard Antivirus", style, CW_USEDEFAULT, CW_USEDEFAULT,
                                client.right - client.left, client.bottom - client.top, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, startHidden ? SW_HIDE : nCmdShow);
    UpdateWindow(hwnd);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g.instanceMutex) CloseHandle(g.instanceMutex);
    Gdiplus::GdiplusShutdown(g.gdiplusToken);
    OleUninitialize();
    return static_cast<int>(m.wParam);
}
