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
#include "openguard/updater.h"
#include "openguard/yara_lite.h"

#include <windows.h>
#include <windowsx.h>
#include <ole2.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifndef OPENGUARD_VERSION
#define OPENGUARD_VERSION "0.2.0"
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "comdlg32.lib")

namespace {

namespace fs = std::filesystem;

// ----------------------------------------------------------------------------- paleta

constexpr COLORREF C_SIDE = RGB(13, 33, 55);
constexpr COLORREF C_SIDE_HOT = RGB(24, 52, 82);
constexpr COLORREF C_ACCENT = RGB(0, 168, 142);
constexpr COLORREF C_ACCENT_HOT = RGB(0, 140, 118);
constexpr COLORREF C_BG = RGB(243, 246, 249);
constexpr COLORREF C_CARD = RGB(255, 255, 255);
constexpr COLORREF C_BORDER = RGB(221, 228, 235);
constexpr COLORREF C_TEXT = RGB(27, 42, 58);
constexpr COLORREF C_MUTED = RGB(105, 120, 135);
constexpr COLORREF C_OK = RGB(31, 163, 99);
constexpr COLORREF C_WARN = RGB(236, 160, 0);
constexpr COLORREF C_BAD = RGB(214, 69, 69);
constexpr COLORREF C_WHITE = RGB(255, 255, 255);
constexpr COLORREF C_SIDE_TEXT = RGB(190, 205, 220);

// ----------------------------------------------------------------------------- ids y mensajes

enum Page { PG_HOME, PG_SCAN, PG_UPDATE, PG_QUARANTINE, PG_REPORTS, PG_SETTINGS, PG_COUNT };

enum : int {
    NAV_BASE = 100,                       // NAV_BASE + Page
    ID_SCAN_QUICK = 200, ID_SCAN_FULL, ID_SCAN_FOLDER, ID_CANCEL, ID_ISOLATE,
    ID_UPDATE_NOW, ID_IMPORT_FILE, ID_Q_RESTORE, ID_Q_DELETE, ID_Q_REFRESH,
    ID_LOG_OPEN, ID_LOG_REFRESH, ID_TOGGLE_PROTECTION, ID_SAVE_SETTINGS, ID_FIX,
    ID_APP_CHECK, ID_APP_INSTALL, ID_APP_PAGE,
    TOG_AUTOQ = 300, TOG_DECOY, TOG_USB, TOG_NOTIFY, TOG_APPUPD
};

constexpr UINT WM_APP_PROGRESS = WM_APP + 1;
constexpr UINT WM_APP_DONE = WM_APP + 2;
constexpr UINT WM_APP_TRAY = WM_APP + 3;
constexpr UINT WM_APP_UPDATE_DONE = WM_APP + 4;
constexpr UINT WM_APP_APPCHECK_DONE = WM_APP + 5;
constexpr UINT WM_APP_APPDL_DONE = WM_APP + 6;
constexpr UINT_PTR TIMER_REFRESH = 1;
constexpr UINT_PTR TIMER_LOGPOLL = 2;
constexpr UINT_PTR TIMER_APPCHECK = 3;
constexpr int IDC_LIST = 1001;
constexpr int IDC_PROGRESS = 1002;

enum class Svc { NotInstalled, Stopped, Running, Pending };

struct HitBox { RECT r; int id; };

struct Settings { bool autoQuarantine{true}, decoys{true}, scanUsb{true}, notify{true}, checkAppUpdates{true}; };

struct DownloadResult { bool ok{false}; std::wstring path; std::wstring error; };

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
    std::vector<openguard::QuarantineItem> quarantined;
    std::wstring scanStatus, updateMsg;
    bool updateOk{true};
    Settings settings;
} g;

int S(int v) { return static_cast<int>(v * g.scale + 0.5); }
RECT R(int l, int t, int r, int b) { RECT rc{l, t, r, b}; return rc; }
std::wstring W(const std::string& utf8) { return openguard::paths::fromUtf8(utf8).wstring(); }

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

void loadSettings() {
    g.settings.autoQuarantine = iniGetBool(serviceIni(), L"service", L"auto_quarantine", true);
    g.settings.decoys = iniGetBool(serviceIni(), L"service", L"decoys", true);
    g.settings.scanUsb = iniGetBool(serviceIni(), L"service", L"scan_usb", true);
    g.settings.notify = iniGetBool(guiIni(), L"gui", L"notifications", true);
    g.settings.checkAppUpdates = iniGetBool(guiIni(), L"gui", L"check_app_updates", true);
}

bool saveSettings() {
    const fs::path ini = serviceIni();
    const BOOL a = WritePrivateProfileStringW(L"service", L"auto_quarantine", g.settings.autoQuarantine ? L"1" : L"0", ini.c_str());
    const BOOL b = WritePrivateProfileStringW(L"service", L"decoys", g.settings.decoys ? L"1" : L"0", ini.c_str());
    const BOOL c = WritePrivateProfileStringW(L"service", L"scan_usb", g.settings.scanUsb ? L"1" : L"0", ini.c_str());
    iniSetStr(guiIni(), L"gui", L"notifications", g.settings.notify ? L"1" : L"0");
    iniSetStr(guiIni(), L"gui", L"check_app_updates", g.settings.checkAppUpdates ? L"1" : L"0");
    return a && b && c;
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
    y.loadDirectory(openguard::paths::signaturesDir() / "yara_rules");
    g.yaraCount = y.ruleCount();
}

openguard::ScannerConfig makeConfig() {
    openguard::ScannerConfig cfg;
    cfg.excludedPaths = { openguard::paths::dataDir(), openguard::paths::executableDir(), openguard::paths::signaturesDir() };
    cfg.yaraRulesDir = openguard::paths::signaturesDir() / "yara_rules";
    return cfg;
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

void fillRect(HDC hdc, RECT rc, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c);
    FillRect(hdc, &rc, b);
    DeleteObject(b);
}

void roundRect(HDC hdc, RECT rc, int radius, COLORREF fill, COLORREF border, bool hasBorder) {
    HBRUSH b = CreateSolidBrush(fill);
    HPEN p = hasBorder ? CreatePen(PS_SOLID, 1, border) : static_cast<HPEN>(GetStockObject(NULL_PEN));
    HGDIOBJ ob = SelectObject(hdc, b);
    HGDIOBJ op = SelectObject(hdc, p);
    RoundRect(hdc, rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);
    if (hasBorder) DeleteObject(p);
}

void text(HDC hdc, const std::wstring& s, RECT rc, HFONT f, COLORREF c,
          UINT fmt = DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX) {
    HGDIOBJ old = SelectObject(hdc, f);
    SetTextColor(hdc, c);
    DrawTextW(hdc, s.c_str(), -1, &rc, fmt);
    SelectObject(hdc, old);
}

void addHit(RECT rc, int id) { g.hits.push_back({rc, id}); }
bool isHot(int id) { return g.hover == id; }

void drawShield(HDC hdc, int cx, int cy, int size, COLORREF fill, COLORREF check) {
    static const double pts[8][2] = {{0, -1}, {0.85, -0.72}, {0.85, 0.1}, {0.6, 0.6}, {0, 1}, {-0.6, 0.6}, {-0.85, 0.1}, {-0.85, -0.72}};
    POINT p[8];
    for (int i = 0; i < 8; ++i) {
        p[i].x = cx + static_cast<LONG>(pts[i][0] * size / 2);
        p[i].y = cy + static_cast<LONG>(pts[i][1] * size / 2);
    }
    HBRUSH b = CreateSolidBrush(fill);
    HGDIOBJ ob = SelectObject(hdc, b);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    Polygon(hdc, p, 8);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);

    LOGBRUSH lb{BS_SOLID, check, 0};
    HPEN pen = ExtCreatePen(PS_GEOMETRIC | PS_SOLID | PS_ENDCAP_ROUND | PS_JOIN_ROUND, std::max(2, size / 11), &lb, 0, nullptr);
    HGDIOBJ opn = SelectObject(hdc, pen);
    POINT c[3] = {{cx - size * 22 / 100, cy + size * 2 / 100}, {cx - size * 6 / 100, cy + size * 20 / 100}, {cx + size * 26 / 100, cy - size * 16 / 100}};
    Polyline(hdc, c, 3);
    SelectObject(hdc, opn);
    DeleteObject(pen);
}

enum BtnStyle { BS_PRIMARY, BS_SECONDARY, BS_DANGER, BS_ONBANNER };

void drawButton(HDC hdc, RECT rc, const std::wstring& label, int id, BtnStyle style, bool enabled = true,
                COLORREF bannerColor = C_ACCENT) {
    const bool hot = enabled && isHot(id);
    COLORREF fill = C_ACCENT, border = C_ACCENT, fg = C_WHITE;
    bool hasBorder = false;
    switch (style) {
        case BS_PRIMARY:   fill = hot ? C_ACCENT_HOT : C_ACCENT; break;
        case BS_DANGER:    fill = hot ? RGB(185, 52, 52) : C_BAD; break;
        case BS_SECONDARY: fill = hot ? RGB(232, 240, 246) : C_CARD; border = C_BORDER; fg = C_TEXT; hasBorder = true; break;
        case BS_ONBANNER:  fill = hot ? RGB(235, 245, 240) : C_WHITE; fg = bannerColor; break;
    }
    if (!enabled) { fill = RGB(226, 231, 236); fg = RGB(150, 160, 170); hasBorder = false; }
    roundRect(hdc, rc, S(8), fill, border, hasBorder);
    text(hdc, label, rc, g.fBold, fg, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    if (enabled) addHit(rc, id);
}

void drawCard(HDC hdc, RECT rc) { roundRect(hdc, rc, S(12), C_CARD, C_BORDER, true); }

void drawCardButton(HDC hdc, RECT rc, const std::wstring& title, const std::wstring& desc, int id, bool enabled = true) {
    const bool hot = enabled && isHot(id);
    roundRect(hdc, rc, S(12), hot ? RGB(240, 251, 249) : C_CARD, hot ? C_ACCENT : C_BORDER, true);
    RECT t = R(rc.left + S(18), rc.top + S(16), rc.right - S(18), rc.top + S(44));
    text(hdc, title, t, g.fH2, enabled ? C_TEXT : C_MUTED, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
    RECT d = R(rc.left + S(18), rc.top + S(48), rc.right - S(18), rc.bottom - S(12));
    text(hdc, desc, d, g.fSmall, C_MUTED);
    if (enabled) addHit(rc, id);
}

void drawToggle(HDC hdc, int x, int y, bool on, int id) {
    RECT rc = R(x, y, x + S(46), y + S(24));
    roundRect(hdc, rc, S(24), on ? C_ACCENT : RGB(190, 200, 210), C_BORDER, false);
    const int knob = S(18);
    const int kx = on ? rc.right - knob - S(3) : rc.left + S(3);
    HBRUSH b = CreateSolidBrush(C_WHITE);
    HGDIOBJ ob = SelectObject(hdc, b);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    Ellipse(hdc, kx, rc.top + S(3), kx + knob, rc.top + S(3) + knob);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);
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
    } else if (g.page == PG_QUARANTINE || g.page == PG_REPORTS) {
        showList = true;
    }

    ShowWindow(g.list, showList ? SW_SHOW : SW_HIDE);
    ShowWindow(g.progress, showProgress ? SW_SHOW : SW_HIDE);
    if (showList) MoveWindow(g.list, body.left, listTop, body.right - body.left, listBottom - listTop, TRUE);
    if (showProgress) MoveWindow(g.progress, body.left, body.top + S(100) + S(16) + S(30), body.right - body.left, S(8), TRUE);
}

void showPage(Page p) {
    g.page = p;
    refreshData();
    if (p == PG_SCAN) fillThreatList();
    else if (p == PG_QUARANTINE) fillQuarantineList();
    else if (p == PG_REPORTS) fillReportList();
    else if (p == PG_SETTINGS) loadSettings();
    layoutControls();
    InvalidateRect(g.main, nullptr, FALSE);
}

// ----------------------------------------------------------------------------- análisis

void startScan(std::vector<fs::path> targets, openguard::ScanType type) {
    if (g.scanning.exchange(true)) return;
    if (g.worker.joinable()) g.worker.join();

    g.threats.clear();
    g.processed = 0;
    g.scanStatus = L"Analizando...";
    if (g.page != PG_SCAN) showPage(PG_SCAN); else fillThreatList();
    SendMessageW(g.progress, PBM_SETMARQUEE, TRUE, 30);
    InvalidateRect(g.main, nullptr, FALSE);

    {
        std::lock_guard<std::mutex> lock(g.scannerMutex);
        g.scanner = std::make_shared<openguard::FileScanner>(g.db, makeConfig());
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
    SendMessageW(g.progress, PBM_SETMARQUEE, FALSE, 0);

    g.threats.clear();
    for (const auto& r : owned->results) if (r.isThreat()) g.threats.push_back(r);
    if (g.page == PG_SCAN) fillThreatList();

    g.scanStatus = L"Completado: " + std::to_wstring(owned->filesScanned) + L" archivos analizados, " +
                   std::to_wstring(owned->threatsFound) + L" amenazas, " +
                   std::to_wstring(owned->duration.count() / 1000) + L" s";
    iniSetStr(guiIni(), L"stats", L"last_scan", nowText());
    iniSetStr(guiIni(), L"stats", L"last_threats", std::to_wstring(owned->threatsFound));
    refreshData();
    InvalidateRect(g.main, nullptr, FALSE);
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
            if (vault.quarantineFile(r.filePath, first.name, first.severity, r.sha256)) { ++ok; done.push_back(static_cast<size_t>(row)); }
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
    } else {
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
            wchar_t tmp[MAX_PATH]{};
            GetTempPathW(MAX_PATH, tmp);
            const fs::path dest = fs::path(tmp) / fs::path(W(info.installerName.empty() ? std::string("OpenGuard_Setup.exe") : info.installerName));
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
        if (reinterpret_cast<INT_PTR>(ShellExecuteW(g.main, L"open", owned->path.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) > 32) {
            PostMessageW(g.main, WM_CLOSE, 0, 0);
        } else {
            MessageBoxW(g.main, (L"No se pudo iniciar el instalador. Puede ejecutarlo manualmente desde:\n" + owned->path).c_str(),
                        L"OpenGuard", MB_OK | MB_ICONWARNING);
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
    fillRect(hdc, R(0, 0, sw, h), C_SIDE);

    if (g.icon) DrawIconEx(hdc, S(20), S(22), g.icon, S(44), S(44), 0, nullptr, DI_NORMAL);
    text(hdc, L"OpenGuard", R(S(72), S(22), sw - S(8), S(46)), g.fH2, C_WHITE, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, L"Antivirus", R(S(72), S(44), sw - S(8), S(66)), g.fSmall, C_SIDE_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);

    static const wchar_t* names[PG_COUNT] = {L"Inicio", L"Analisis", L"Actualizacion", L"Cuarentena", L"Informes", L"Configuracion"};
    static const wchar_t* glyphs[PG_COUNT] = {L"\xE80F", L"\xE721", L"\xE895", L"\xE72E", L"\xE8A5", L"\xE713"};
    int y = S(104);
    for (int i = 0; i < PG_COUNT; ++i) {
        RECT item = R(0, y, sw, y + S(48));
        const bool sel = (g.page == i);
        if (sel || isHot(NAV_BASE + i)) fillRect(hdc, item, C_SIDE_HOT);
        if (sel) fillRect(hdc, R(0, y, S(4), y + S(48)), C_ACCENT);
        text(hdc, glyphs[i], R(S(24), y, S(52), y + S(48)), g.fIcon, sel ? C_ACCENT : C_SIDE_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, names[i], R(S(62), y, sw - S(8), y + S(48)), g.fBody, sel ? C_WHITE : C_SIDE_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        addHit(item, NAV_BASE + i);
        y += S(52);
    }

    // Estado del servicio y versión al pie
    const bool on = (g.svc == Svc::Running);
    HBRUSH b = CreateSolidBrush(on ? C_OK : C_BAD);
    HGDIOBJ ob = SelectObject(hdc, b);
    HGDIOBJ op = SelectObject(hdc, GetStockObject(NULL_PEN));
    Ellipse(hdc, S(24), h - S(70), S(34), h - S(60));
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(b);
    text(hdc, on ? L"Proteccion activa" : L"Proteccion inactiva", R(S(42), h - S(76), sw - S(8), h - S(54)), g.fSmall, C_SIDE_TEXT, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, W(std::string("Version ") + OPENGUARD_VERSION), R(S(24), h - S(46), sw - S(8), h - S(24)), g.fSmall, RGB(120, 140, 160), DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
}

void pageHeader(HDC hdc, int w, const std::wstring& title, const std::wstring& subtitle) {
    text(hdc, title, R(S(264), S(28), w - S(28), S(66)), g.fH1, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, subtitle, R(S(264), S(66), w - S(28), S(92)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
}

void paintHome(HDC hdc, int w, int h) {
    pageHeader(hdc, w, L"Inicio", L"Estado general de la proteccion de su equipo");
    const RECT body = bodyRect(w, h);
    const int bw = body.right - body.left;

    // Banner de estado
    const Status st = computeStatus();
    RECT banner = R(body.left, body.top, body.right, body.top + S(160));
    roundRect(hdc, banner, S(16), st.color, st.color, false);
    drawShield(hdc, banner.left + S(86), banner.top + S(80), S(96), C_WHITE, st.color);
    text(hdc, st.title, R(banner.left + S(166), banner.top + S(28), banner.right - S(24), banner.top + S(72)), g.fBig, C_WHITE, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, st.subtitle, R(banner.left + S(166), banner.top + S(76), banner.right - S(24), banner.top + S(116)), g.fBody, C_WHITE);
    if (st.actionId != 0) {
        drawButton(hdc, R(banner.left + S(166), banner.bottom - S(50), banner.left + S(166) + S(200), banner.bottom - S(14)),
                   st.action, st.actionId, BS_ONBANNER, true, st.color);
    }

    // Aviso de nueva versión del programa
    int extra = 0;
    if (g.appInfo.available) {
        RECT strip = R(body.left, banner.bottom + S(12), body.right, banner.bottom + S(12) + S(46));
        roundRect(hdc, strip, S(10), RGB(228, 240, 252), RGB(150, 190, 230), true);
        text(hdc, L"Nueva version disponible: OpenGuard " + W(g.appInfo.latestVersion),
             R(strip.left + S(18), strip.top, strip.right - S(200), strip.bottom), g.fBold, RGB(20, 70, 130), DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        drawButton(hdc, R(strip.right - S(180), strip.top + S(7), strip.right - S(10), strip.bottom - S(7)), L"Ver actualizacion", NAV_BASE + PG_UPDATE, BS_PRIMARY);
        extra = S(58);
    }

    // Tarjetas de acciones
    const int gap = S(16);
    const int cw = (bw - 3 * gap) / 4;
    const int ctop = banner.bottom + S(22) + extra;
    const int ch = S(124);
    drawCardButton(hdc, R(body.left, ctop, body.left + cw, ctop + ch), L"Analisis rapido",
                   L"Descargas, Escritorio, Documentos y Temp", ID_SCAN_QUICK, !g.scanning);
    drawCardButton(hdc, R(body.left + (cw + gap), ctop, body.left + (cw + gap) + cw, ctop + ch), L"Analisis completo",
                   L"Todas las unidades fijas del equipo", ID_SCAN_FULL, !g.scanning);
    drawCardButton(hdc, R(body.left + 2 * (cw + gap), ctop, body.left + 2 * (cw + gap) + cw, ctop + ch), L"Actualizacion",
                   std::to_wstring(g.sigCount) + L" firmas y " + std::to_wstring(g.yaraCount) + L" reglas YARA", NAV_BASE + PG_UPDATE);
    drawCardButton(hdc, R(body.left + 3 * (cw + gap), ctop, body.left + 3 * (cw + gap) + cw, ctop + ch), L"Cuarentena",
                   std::to_wstring(g.quarantineCount) + L" elementos aislados", NAV_BASE + PG_QUARANTINE);

    // Resumen
    RECT info = R(body.left, ctop + ch + S(22), body.right, std::min<int>(body.bottom, ctop + ch + S(22) + S(150)));
    if (info.bottom - info.top < S(60)) return; // ventana muy baja: se omite el resumen
    drawCard(hdc, info);
    const std::wstring lastScan = iniGetStr(guiIni(), L"stats", L"last_scan", L"Nunca");
    const std::wstring lastThreats = iniGetStr(guiIni(), L"stats", L"last_threats", L"-");
    const std::wstring lastUpdate = iniGetStr(guiIni(), L"stats", L"last_update", L"Nunca");
    const wchar_t* svcText = g.svc == Svc::Running ? L"Activa" : g.svc == Svc::NotInstalled ? L"No instalada" : g.svc == Svc::Pending ? L"Cambiando de estado" : L"Desactivada";
    const std::pair<std::wstring, std::wstring> rows[] = {
        {L"Proteccion en tiempo real", svcText},
        {L"Ultimo analisis", lastScan + (lastThreats == L"-" ? L"" : L"  (" + lastThreats + L" amenazas)")},
        {L"Ultima actualizacion de firmas", lastUpdate},
        {L"Motor", W(std::string("OpenGuard ") + OPENGUARD_VERSION) + L"  |  Firmas + YARA + Heuristica PE/Scripts"},
    };
    int ry = info.top + S(16);
    const int maxRows = std::max(1, (info.bottom - info.top - S(20)) / S(30));
    int shown = 0;
    for (const auto& row : rows) {
        if (shown++ >= maxRows) break;
        text(hdc, row.first, R(info.left + S(20), ry, info.left + S(300), ry + S(26)), g.fBody, C_MUTED, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, row.second, R(info.left + S(310), ry, info.right - S(20), ry + S(26)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        ry += S(30);
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
        statusColor = RGB(20, 110, 190);
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

    struct Row { const wchar_t* title; const wchar_t* desc; bool* value; int id; };
    Row rows[] = {
        {L"Aislar amenazas confirmadas automaticamente", L"Mueve a cuarentena los archivos que coinciden con una firma o tienen riesgo critico.", &g.settings.autoQuarantine, TOG_AUTOQ},
        {L"Archivos senuelo anti-ransomware", L"Crea archivos ocultos en Documentos y Escritorio y alerta si alguien los modifica.", &g.settings.decoys, TOG_DECOY},
        {L"Analizar unidades USB al conectarlas", L"Revisa automaticamente las memorias y discos extraibles nuevos.", &g.settings.scanUsb, TOG_USB},
        {L"Mostrar notificaciones en la bandeja", L"Avisa cuando el servicio detecta o aisla una amenaza.", &g.settings.notify, TOG_NOTIFY},
        {L"Buscar actualizaciones del programa automaticamente", L"Comprueba en GitHub si hay una version nueva de OpenGuard al abrir la aplicacion.", &g.settings.checkAppUpdates, TOG_APPUPD},
    };
    const int rowH = S(64);
    RECT card = R(body.left, body.top, body.right, body.top + rowH * 5 + S(8));
    drawCard(hdc, card);
    int y = card.top + S(4);
    for (const auto& r : rows) {
        text(hdc, r.title, R(card.left + S(22), y + S(10), card.right - S(100), y + S(34)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
        text(hdc, r.desc, R(card.left + S(22), y + S(34), card.right - S(100), y + rowH - S(4)), g.fSmall, C_MUTED);
        drawToggle(hdc, card.right - S(76), y + (rowH - S(24)) / 2, *r.value, r.id);
        y += rowH;
        if (&r != &rows[4]) fillRect(hdc, R(card.left + S(20), y - 1, card.right - S(20), y), C_BORDER);
    }

    const int py = card.bottom + S(14);
    RECT pc = R(body.left, py, body.right, py + S(72));
    drawCard(hdc, pc);
    const bool running = (g.svc == Svc::Running);
    text(hdc, L"Proteccion en tiempo real", R(pc.left + S(22), pc.top + S(12), pc.right - S(260), pc.top + S(36)), g.fBold, C_TEXT, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    text(hdc, running ? L"El servicio esta en ejecucion." : (g.svc == Svc::NotInstalled ? L"El servicio no esta instalado." : L"El servicio esta detenido."),
         R(pc.left + S(22), pc.top + S(38), pc.right - S(260), pc.top + S(64)), g.fSmall, running ? C_OK : C_BAD, DT_LEFT | DT_SINGLELINE | DT_NOPREFIX);
    drawButton(hdc, R(pc.right - S(236), pc.top + S(18), pc.right - S(20), pc.top + S(58)),
               running ? L"Desactivar proteccion" : L"Activar proteccion", ID_TOGGLE_PROTECTION, running ? BS_SECONDARY : BS_PRIMARY);

    const int by = bottomButtonsTop(h);
    drawButton(hdc, R(body.left, by, body.left + S(260), by + S(40)), L"Guardar y aplicar", ID_SAVE_SETTINGS, BS_PRIMARY);
}

void paintAll(HDC hdc, int w, int h) {
    g.hits.clear();
    SetBkMode(hdc, TRANSPARENT);
    fillRect(hdc, R(0, 0, w, h), C_BG);
    paintSidebar(hdc, h);
    switch (g.page) {
        case PG_HOME:       paintHome(hdc, w, h); break;
        case PG_SCAN:       paintScan(hdc, w, h); break;
        case PG_UPDATE:     paintUpdate(hdc, w, h); break;
        case PG_QUARANTINE: paintQuarantine(hdc, w, h); break;
        case PG_REPORTS:    paintReports(hdc, w, h); break;
        case PG_SETTINGS:   paintSettings(hdc, w, h); break;
        default: break;
    }
}

// ----------------------------------------------------------------------------- eventos

void onHit(int id) {
    if (id >= NAV_BASE && id < NAV_BASE + PG_COUNT) { showPage(static_cast<Page>(id - NAV_BASE)); return; }

    switch (id) {
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
        case TOG_AUTOQ: g.settings.autoQuarantine = !g.settings.autoQuarantine; break;
        case TOG_DECOY: g.settings.decoys = !g.settings.decoys; break;
        case TOG_USB: g.settings.scanUsb = !g.settings.scanUsb; break;
        case TOG_NOTIFY: g.settings.notify = !g.settings.notify; break;
        case TOG_APPUPD: g.settings.checkAppUpdates = !g.settings.checkAppUpdates; break;
        case ID_APP_CHECK: startAppCheck(false); break;
        case ID_APP_INSTALL: startAppInstall(); break;
        case ID_APP_PAGE:
            if (g.appInfo.pageUrl.rfind("https://", 0) == 0) ShellExecuteW(g.main, L"open", W(g.appInfo.pageUrl).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            break;
        case ID_SAVE_SETTINGS:
            if (!saveSettings()) {
                MessageBoxW(g.main, L"No se pudo guardar la configuracion del servicio.", L"OpenGuard", MB_OK | MB_ICONWARNING);
            } else if (queryService() == Svc::Running) {
                std::wstring err;
                setProtection(false, err);
                setProtection(true, err);
                refreshData();
                MessageBoxW(g.main, L"Configuracion guardada. La proteccion se reinicio para aplicar los cambios.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(g.main, L"Configuracion guardada.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
            }
            break;
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

HFONT makeFont(int px, int weight, const wchar_t* face = L"Segoe UI") {
    return CreateFontW(-S(px), 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g.main = hwnd;
            g.fH1 = makeFont(26, FW_SEMIBOLD);
            g.fH2 = makeFont(16, FW_SEMIBOLD);
            g.fBig = makeFont(30, FW_SEMIBOLD);
            g.fBody = makeFont(14, FW_NORMAL);
            g.fBold = makeFont(14, FW_SEMIBOLD);
            g.fSmall = makeFont(12, FW_NORMAL);
            g.fIcon = makeFont(18, FW_NORMAL, L"Segoe MDL2 Assets");
            g.icon = static_cast<HICON>(LoadImageW(g.hInst, MAKEINTRESOURCEW(1), IMAGE_ICON, S(48), S(48), LR_DEFAULTCOLOR));

            g.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                     WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                                     0, 0, 10, 10, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LIST)), g.hInst, nullptr);
            ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            SendMessageW(g.list, WM_SETFONT, reinterpret_cast<WPARAM>(g.fBody), TRUE);

            g.progress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | PBS_MARQUEE, 0, 0, 10, 10, hwnd,
                                         reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PROGRESS)), g.hInst, nullptr);

            loadSettings();
            refreshData();
            loadYaraCount();
            layoutControls();
            addTrayIcon();
            SetTimer(hwnd, TIMER_REFRESH, 5000, nullptr);
            SetTimer(hwnd, TIMER_LOGPOLL, 5000, nullptr);
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
            HDC mem = CreateCompatibleDC(hdc);
            HBITMAP bmp = CreateCompatibleBitmap(hdc, w, h);
            HGDIOBJ old = SelectObject(mem, bmp);
            paintAll(mem, w, h);
            BitBlt(hdc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = S(980);
            mmi->ptMinTrackSize.y = S(660);
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
            if (wp == TIMER_LOGPOLL) { pollServiceLog(); return 0; }
            if (wp == TIMER_APPCHECK) { if (g.settings.checkAppUpdates) startAppCheck(true); return 0; }
            if (wp == TIMER_REFRESH && !g.scanning) { refreshData(); InvalidateRect(hwnd, nullptr, FALSE); }
            return 0;
        case WM_APP_PROGRESS:
            g.scanStatus = L"Analizando... " + std::to_wstring(static_cast<size_t>(wp)) + L" archivos procesados";
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_APP_DONE:
            onScanDone(reinterpret_cast<openguard::ScanSessionStats*>(lp));
            return 0;
        case WM_APP_APPCHECK_DONE:
            onAppCheckDone(reinterpret_cast<openguard::AppUpdateInfo*>(lp));
            return 0;
        case WM_APP_APPDL_DONE:
            onAppDownloadDone(reinterpret_cast<DownloadResult*>(lp));
            return 0;
        case WM_APP_UPDATE_DONE:
            onUpdateDone(reinterpret_cast<openguard::UpdateResult*>(lp));
            return 0;
        case WM_APP_TRAY:
            if (LOWORD(lp) == WM_LBUTTONDBLCLK || LOWORD(lp) == NIN_BALLOONUSERCLICK) {
                ShowWindow(hwnd, SW_SHOWNORMAL);
                SetForegroundWindow(hwnd);
                if (LOWORD(lp) == NIN_BALLOONUSERCLICK) showPage(PG_REPORTS);
            }
            return 0;
        case WM_CLOSE:
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
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    OleUninitialize();
    return static_cast<int>(m.wParam);
}
