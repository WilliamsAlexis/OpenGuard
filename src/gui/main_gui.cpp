/**
 * @file main_gui.cpp
 * @brief Interfaz gráfica de OpenGuard (Win32 nativo + ListView, sin dependencias externas).
 * @details Ventana única con: análisis rápido / completo / de carpeta, lista de amenazas con opción de
 *          aislarlas, gestor de cuarentena (restaurar / eliminar), estado del servicio de tiempo real
 *          y visor del registro. Los análisis corren en un hilo; la UI se actualiza con mensajes.
 */

#include "openguard/paths.h"
#include "openguard/quarantine.h"
#include "openguard/scanner.h"
#include "openguard/signatures.h"

#include <windows.h>
#include <ole2.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
// Controles visuales modernos (Common Controls 6)
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

namespace {

namespace fs = std::filesystem;

enum : int {
    IDC_QUICK = 101, IDC_FULL, IDC_FOLDER, IDC_QUARANTINE, IDC_LOG, IDC_CANCEL,
    IDC_ACTION1, IDC_ACTION2, IDC_LIST, IDC_STATUS
};
constexpr UINT WM_APP_PROGRESS = WM_APP + 1;
constexpr UINT WM_APP_DONE = WM_APP + 2;
constexpr UINT WM_APP_TRAY = WM_APP + 3;
constexpr UINT_PTR TIMER_STATUS = 1;
constexpr UINT_PTR TIMER_LOGPOLL = 2;

enum class Mode { Results, Quarantine };

struct AppState {
    HWND main{}, list{}, status{};
    HWND btnQuick{}, btnFull{}, btnFolder{}, btnQuarantine{}, btnLog{}, btnCancel{}, btnAction1{}, btnAction2{};
    std::shared_ptr<openguard::SignatureDB> db;
    std::shared_ptr<openguard::FileScanner> scanner;
    std::mutex scannerMutex;
    std::thread worker;
    std::atomic<bool> scanning{false};
    std::atomic<size_t> processed{0};
    Mode mode{Mode::Results};
    std::vector<openguard::ScanResult> threats;           // modo Results
    std::vector<openguard::QuarantineItem> quarantined;   // modo Quarantine
    HFONT font{};
} g;

std::wstring W(const std::string& utf8) { return openguard::paths::fromUtf8(utf8).wstring(); }

void setStatus(const std::wstring& text) { SetWindowTextW(g.status, text.c_str()); }

std::wstring serviceStateText() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return L"desconocido";
    std::wstring text = L"no instalado";
    if (SC_HANDLE svc = OpenServiceW(scm, L"OpenGuardService", SERVICE_QUERY_STATUS)) {
        SERVICE_STATUS st{};
        text = L"desconocido";
        if (QueryServiceStatus(svc, &st)) {
            text = st.dwCurrentState == SERVICE_RUNNING ? L"ACTIVO"
                 : st.dwCurrentState == SERVICE_STOPPED ? L"DETENIDO" : L"en transicion";
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return text;
}

void refreshHeaderStatus() {
    size_t sigs = g.db ? g.db->getStats().totalSignatures : 0;
    setStatus(L"Proteccion en tiempo real: " + serviceStateText() + L"   |   Firmas: " + std::to_wstring(sigs));
}

openguard::ScannerConfig makeConfig() {
    openguard::ScannerConfig cfg;
    cfg.excludedPaths = { openguard::paths::dataDir(), openguard::paths::executableDir(), openguard::paths::signaturesDir() };
    cfg.yaraRulesDir = openguard::paths::signaturesDir() / "yara_rules";
    return cfg;
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
        col.cx = c.second;
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

void updateButtons() {
    const bool busy = g.scanning;
    EnableWindow(g.btnQuick, !busy);
    EnableWindow(g.btnFull, !busy);
    EnableWindow(g.btnFolder, !busy);
    EnableWindow(g.btnQuarantine, !busy);
    EnableWindow(g.btnCancel, busy);
    EnableWindow(g.btnAction1, !busy);
    EnableWindow(g.btnAction2, !busy && g.mode == Mode::Quarantine);
    SetWindowTextW(g.btnAction1, g.mode == Mode::Results ? L"Aislar seleccionados" : L"Restaurar");
    SetWindowTextW(g.btnAction2, L"Eliminar definitivamente");
    ShowWindow(g.btnAction2, g.mode == Mode::Quarantine ? SW_SHOW : SW_HIDE);
}

void showResults() {
    g.mode = Mode::Results;
    ListView_DeleteAllItems(g.list);
    setColumns({{L"Archivo", 420}, {L"Amenaza", 260}, {L"Riesgo", 90}});
    int row = 0;
    for (const auto& r : g.threats) {
        std::wstring names;
        for (const auto& t : r.threats) { if (!names.empty()) names += L", "; names += W(t.name); }
        addRow(row++, {r.filePath.wstring(), names, std::wstring(riskName(r.riskLevel)) + L" (" + std::to_wstring(r.riskScore) + L")"});
    }
    updateButtons();
}

void showQuarantine() {
    g.mode = Mode::Quarantine;
    try {
        openguard::QuarantineVault vault(openguard::paths::quarantineDir());
        g.quarantined = vault.listItems();
    } catch (...) {
        g.quarantined.clear();
    }
    ListView_DeleteAllItems(g.list);
    setColumns({{L"Ruta original", 400}, {L"Amenaza", 220}, {L"Fecha", 160}});
    int row = 0;
    for (const auto& q : g.quarantined) {
        addRow(row++, {q.originalPath.wstring(), W(q.threatName), W(q.quarantinedAt)});
    }
    setStatus(L"Cuarentena: " + std::to_wstring(g.quarantined.size()) + L" elementos");
    updateButtons();
}

// ----------------------------------------------------------------------------- análisis

void startScan(std::vector<fs::path> targets, openguard::ScanType type) {
    if (g.scanning.exchange(true)) return;
    if (g.worker.joinable()) g.worker.join();

    g.mode = Mode::Results;
    g.threats.clear();
    g.processed = 0;
    showResults();
    updateButtons();
    setStatus(L"Analizando...");

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

    g.threats.clear();
    for (const auto& r : owned->results) if (r.isThreat()) g.threats.push_back(r);
    showResults();

    std::wstring msg = L"Analisis completado: " + std::to_wstring(owned->filesScanned) + L" archivos, " +
                       std::to_wstring(owned->threatsFound) + L" amenazas, " +
                       std::to_wstring(owned->duration.count() / 1000) + L" s";
    setStatus(msg);
    if (owned->threatsFound == 0) {
        MessageBoxW(g.main, L"No se encontraron amenazas.", L"OpenGuard", MB_OK | MB_ICONINFORMATION);
    }
}

void quarantineSelected() {
    const auto rows = selectedRows();
    if (rows.empty()) { MessageBoxW(g.main, L"Seleccione al menos una amenaza.", L"OpenGuard", MB_OK | MB_ICONINFORMATION); return; }

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
    showResults();

    std::wstring msg = std::to_wstring(ok) + L" aislados, " + std::to_wstring(fail) + L" con error.";
    if (fail) msg += L"\n\nSi falla, ejecute OpenGuard como Administrador o cierre el programa que usa el archivo.";
    MessageBoxW(g.main, msg.c_str(), L"Cuarentena", MB_OK | (fail ? MB_ICONWARNING : MB_ICONINFORMATION));
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
            const std::string& qid = g.quarantined[static_cast<size_t>(row)].qid;
            if (restore ? vault.restoreFile(qid) : vault.deletePermanently(qid)) ++ok; else ++fail;
        }
    } catch (...) { fail = static_cast<int>(rows.size()); }

    showQuarantine();
    std::wstring msg = std::to_wstring(ok) + L" correctos, " + std::to_wstring(fail) + L" con error.";
    MessageBoxW(g.main, msg.c_str(), L"Cuarentena", MB_OK | (fail ? MB_ICONWARNING : MB_ICONINFORMATION));
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

// ----------------------------------------------------------------------------- bandeja y notificaciones

std::uintmax_t g_logOffset = 0;
NOTIFYICONDATAW g_tray{};

void addTrayIcon() {
    g_tray = {};
    g_tray.cbSize = sizeof(g_tray);
    g_tray.hWnd = g.main;
    g_tray.uID = 1;
    g_tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_tray.uCallbackMessage = WM_APP_TRAY;
    g_tray.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    lstrcpynW(g_tray.szTip, L"OpenGuard Antivirus", static_cast<int>(std::size(g_tray.szTip)));
    Shell_NotifyIconW(NIM_ADD, &g_tray);

    // Solo se notifican eventos posteriores al arranque de la GUI
    std::error_code ec;
    const fs::path log = openguard::paths::logsDir() / "service.log";
    g_logOffset = fs::exists(log, ec) ? fs::file_size(log, ec) : 0;
}

void removeTrayIcon() { Shell_NotifyIconW(NIM_DELETE, &g_tray); }

void showBalloon(const std::wstring& title, const std::wstring& text, DWORD icon) {
    NOTIFYICONDATAW n = g_tray;
    n.uFlags = NIF_INFO;
    n.dwInfoFlags = icon;
    lstrcpynW(n.szInfoTitle, title.c_str(), static_cast<int>(std::size(n.szInfoTitle)));
    lstrcpynW(n.szInfo, text.c_str(), static_cast<int>(std::size(n.szInfo)));
    Shell_NotifyIconW(NIM_MODIFY, &n);
}

/// Lee las líneas nuevas del registro del servicio y avisa de alertas y acciones de cuarentena.
void pollServiceLog() {
    const fs::path log = openguard::paths::logsDir() / "service.log";
    std::error_code ec;
    if (!fs::exists(log, ec)) return;
    const std::uintmax_t size = fs::file_size(log, ec);
    if (ec) return;
    if (size < g_logOffset) g_logOffset = 0; // el registro rotó

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

    if (alerts > 0) {
        // Quitar la marca de tiempo "YYYY-MM-DD HH:MM:SS " para el cuerpo del aviso
        std::string body = lastAlert.size() > 20 ? lastAlert.substr(20) : lastAlert;
        showBalloon(alerts > 1 ? L"OpenGuard: " + std::to_wstring(alerts) + L" alertas" : L"OpenGuard: alerta de seguridad",
                    W(body), NIIF_WARNING);
    }
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

// ----------------------------------------------------------------------------- ventana

HWND makeButton(HWND parent, int id, const wchar_t* text) {
    HWND h = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 10, 10,
                             parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);
    return h;
}

void layout(int w, int h) {
    const int margin = 10, bh = 30, gap = 6;
    int x = margin;
    auto place = [&](HWND b, int bw) { MoveWindow(b, x, margin, bw, bh, TRUE); x += bw + gap; };
    place(g.btnQuick, 120); place(g.btnFull, 120); place(g.btnFolder, 130);
    place(g.btnQuarantine, 100); place(g.btnLog, 100); place(g.btnCancel, 90);

    const int listTop = margin * 2 + bh;
    const int bottomBar = bh + margin;
    const int statusH = 22;
    MoveWindow(g.list, margin, listTop, w - 2 * margin, h - listTop - bottomBar - statusH - margin, TRUE);
    int bx = margin;
    const int by = h - bottomBar - statusH;
    MoveWindow(g.btnAction1, bx, by, 170, bh, TRUE);
    MoveWindow(g.btnAction2, bx + 176, by, 190, bh, TRUE);
    MoveWindow(g.status, margin, h - statusH - 4, w - 2 * margin, statusH, TRUE);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_CREATE: {
            g.main = hwnd;
            g.font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            g.btnQuick = makeButton(hwnd, IDC_QUICK, L"Analisis rapido");
            g.btnFull = makeButton(hwnd, IDC_FULL, L"Analisis completo");
            g.btnFolder = makeButton(hwnd, IDC_FOLDER, L"Analizar carpeta...");
            g.btnQuarantine = makeButton(hwnd, IDC_QUARANTINE, L"Cuarentena");
            g.btnLog = makeButton(hwnd, IDC_LOG, L"Registro");
            g.btnCancel = makeButton(hwnd, IDC_CANCEL, L"Cancelar");
            g.btnAction1 = makeButton(hwnd, IDC_ACTION1, L"Aislar seleccionados");
            g.btnAction2 = makeButton(hwnd, IDC_ACTION2, L"Eliminar definitivamente");

            g.list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                                     0, 0, 10, 10, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LIST)),
                                     GetModuleHandleW(nullptr), nullptr);
            ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
            SendMessageW(g.list, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);

            g.status = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hwnd,
                                       reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_STATUS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(g.status, WM_SETFONT, reinterpret_cast<WPARAM>(g.font), TRUE);

            showResults();
            refreshHeaderStatus();
            SetTimer(hwnd, TIMER_STATUS, 10000, nullptr); // refresca el estado del servicio
            addTrayIcon();
            SetTimer(hwnd, TIMER_LOGPOLL, 5000, nullptr); // busca alertas nuevas del servicio
            return 0;
        }
        case WM_SIZE:
            layout(LOWORD(lp), HIWORD(lp));
            return 0;
        case WM_GETMINMAXINFO: {
            auto* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = 760;
            mmi->ptMinTrackSize.y = 380;
            return 0;
        }
        case WM_TIMER:
            if (wp == TIMER_LOGPOLL) { pollServiceLog(); return 0; }
            if (!g.scanning && g.mode == Mode::Results && g.threats.empty()) refreshHeaderStatus();
            return 0;
        case WM_COMMAND:
            switch (LOWORD(wp)) {
                case IDC_QUICK:      startScan(quickTargets(), openguard::ScanType::Quick); break;
                case IDC_FULL:
                    if (MessageBoxW(hwnd, L"El analisis completo recorre todas las unidades y puede tardar mucho. Continuar?",
                                    L"Analisis completo", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                        startScan(openguard::FileScanner::getFixedDrives(), openguard::ScanType::Full);
                    }
                    break;
                case IDC_FOLDER:     chooseFolderAndScan(); break;
                case IDC_QUARANTINE: showQuarantine(); break;
                case IDC_LOG:        openLog(); break;
                case IDC_CANCEL: {
                    std::lock_guard<std::mutex> lock(g.scannerMutex);
                    if (g.scanner) g.scanner->cancelScan();
                    setStatus(L"Cancelando...");
                    break;
                }
                case IDC_ACTION1:
                    if (g.mode == Mode::Results) quarantineSelected(); else quarantineAction(true);
                    break;
                case IDC_ACTION2:    quarantineAction(false); break;
                default: break;
            }
            return 0;
        case WM_APP_TRAY:
            if (LOWORD(lp) == WM_LBUTTONDBLCLK || LOWORD(lp) == NIN_BALLOONUSERCLICK) {
                ShowWindow(hwnd, SW_SHOWNORMAL);
                SetForegroundWindow(hwnd);
                if (LOWORD(lp) == NIN_BALLOONUSERCLICK) openLog();
            }
            return 0;
        case WM_APP_PROGRESS:
            setStatus(L"Analizando... " + std::to_wstring(static_cast<size_t>(wp)) + L" archivos");
            return 0;
        case WM_APP_DONE:
            onScanDone(reinterpret_cast<openguard::ScanSessionStats*>(lp));
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
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

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
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    wc.lpszClassName = L"OpenGuardMainWindow";
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"OpenGuard Antivirus", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, 900, 560, nullptr, nullptr, hInstance, nullptr);
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
