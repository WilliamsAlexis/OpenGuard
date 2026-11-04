/**
 * @file settings.cpp
 * @brief Implementación de la configuración compartida de OpenGuard.
 */

#include "openguard/settings.h"
#include "openguard/paths.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <cwctype>
#include <string>
#include <thread>

namespace openguard {

namespace {

std::filesystem::path defaultIni() { return paths::dataDir() / L"config.ini"; }

std::wstring normalizedLower(const std::filesystem::path& p) {
    std::wstring w = p.lexically_normal().wstring();
    for (auto& c : w) c = static_cast<wchar_t>(towlower(c));
    while (w.size() > 1 && (w.back() == L'\\' || w.back() == L'/')) w.pop_back();
    return w;
}

} // namespace

ProtectionSettings ProtectionSettings::load(const std::filesystem::path& iniPath) {
    const std::filesystem::path ini = iniPath.empty() ? defaultIni() : iniPath;
    const std::wstring f = ini.wstring();

    ProtectionSettings s;
    {
        // threat_action manda; si no existe (instalaciones anteriores) se deriva de auto_quarantine
        wchar_t ta[16]{};
        GetPrivateProfileStringW(L"service", L"threat_action", L"", ta, 16, f.c_str());
        const std::wstring t(ta);
        if (t == L"ask" || t == L"quarantine" || t == L"report") {
            s.threatAction = std::string(t.begin(), t.end());
        } else {
            s.threatAction = GetPrivateProfileIntW(L"service", L"auto_quarantine", 0, f.c_str()) != 0 ? "quarantine" : "ask";
        }
        s.autoQuarantine = (s.threatAction == "quarantine");
    }
    s.decoys = GetPrivateProfileIntW(L"service", L"decoys", 1, f.c_str()) != 0;
    s.scanUsb = GetPrivateProfileIntW(L"service", L"scan_usb", 1, f.c_str()) != 0;
    {
        // Compatibilidad: si no existe usb_mode se deriva de scan_usb (0 = off; cualquier otro caso = preguntar)
        wchar_t mode[16]{};
        GetPrivateProfileStringW(L"service", L"usb_mode", L"", mode, 16, f.c_str());
        const std::wstring m(mode);
        if (m == L"auto" || m == L"ask" || m == L"off") s.usbMode = std::string(m.begin(), m.end());
        else s.usbMode = s.scanUsb ? "ask" : "off";
        s.scanUsb = (s.usbMode != "off");
    }
    s.scanDownloads = GetPrivateProfileIntW(L"service", L"scan_downloads", 1, f.c_str()) != 0;
    s.isolatedScan = GetPrivateProfileIntW(L"service", L"isolated_scan", 1, f.c_str()) != 0;
    s.autoUpdate = GetPrivateProfileIntW(L"updates", L"auto", 1, f.c_str()) != 0;
    s.updateHours = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"updates", L"hours", 6, f.c_str())), 1, 168);
    s.feedRules = GetPrivateProfileIntW(L"updates", L"rules", 1, f.c_str()) != 0;
    s.feedBazaar = GetPrivateProfileIntW(L"updates", L"bazaar", 0, f.c_str()) != 0;
    s.schedule.enabled = GetPrivateProfileIntW(L"schedule", L"enabled", 0, f.c_str()) != 0;
    {
        wchar_t buf[32]{};
        GetPrivateProfileStringW(L"schedule", L"type", L"quick", buf, 32, f.c_str());
        s.schedule.type = (std::wstring(buf) == L"full") ? "full" : "quick";
        GetPrivateProfileStringW(L"schedule", L"frequency", L"daily", buf, 32, f.c_str());
        s.schedule.frequency = (std::wstring(buf) == L"weekly") ? "weekly" : "daily";
    }
    s.schedule.hour = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"schedule", L"hour", 12, f.c_str())), 0, 23);
    s.schedule.minute = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"schedule", L"minute", 0, f.c_str())), 0, 59);
    s.schedule.weekday = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"schedule", L"weekday", 1, f.c_str())), 0, 6);
    s.cpuPercent = std::clamp(static_cast<int>(GetPrivateProfileIntW(L"service", L"cpu_percent", 50, f.c_str())), 10, 100);

    const UINT count = std::min<UINT>(GetPrivateProfileIntW(L"exclusions", L"count", 0, f.c_str()), 500);
    for (UINT i = 0; i < count; ++i) {
        wchar_t buf[2048]{};
        const std::wstring key = L"path" + std::to_wstring(i);
        GetPrivateProfileStringW(L"exclusions", key.c_str(), L"", buf, static_cast<DWORD>(std::size(buf)), f.c_str());
        if (buf[0] != L'\0') s.exclusions.emplace_back(buf);
    }
    return s;
}

bool ProtectionSettings::save(const std::filesystem::path& iniPath) const {
    const std::filesystem::path ini = iniPath.empty() ? defaultIni() : iniPath;
    const std::wstring f = ini.wstring();

    // Los .ini de Windows son ANSI salvo que el archivo empiece con BOM UTF-16: se crea así para
    // conservar rutas de exclusión con cualquier carácter Unicode.
    std::error_code fsec;
    if (!std::filesystem::exists(ini, fsec)) {
        HANDLE h = CreateFileW(f.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            const unsigned char bom[2] = {0xFF, 0xFE};
            DWORD written = 0;
            WriteFile(h, bom, 2, &written, nullptr);
            CloseHandle(h);
        }
    }

    bool ok = true;
    auto put =[&](const wchar_t* sec, const wchar_t* key, const std::wstring& val) {
        ok = WritePrivateProfileStringW(sec, key, val.c_str(), f.c_str()) && ok;
    };
    const std::string action = (threatAction == "quarantine" || threatAction == "report") ? threatAction : "ask";
    put(L"service", L"threat_action", std::wstring(action.begin(), action.end()));
    put(L"service", L"auto_quarantine", action == "quarantine" ? L"1" : L"0");
    put(L"service", L"decoys", decoys ? L"1" : L"0");
    const std::string mode = (usbMode == "auto" || usbMode == "off") ? usbMode : "ask";
    put(L"service", L"scan_usb", mode != "off" ? L"1" : L"0");
    put(L"service", L"usb_mode", std::wstring(mode.begin(), mode.end()));
    put(L"service", L"scan_downloads", scanDownloads ? L"1" : L"0");
    put(L"service", L"isolated_scan", isolatedScan ? L"1" : L"0");
    put(L"updates", L"auto", autoUpdate ? L"1" : L"0");
    put(L"updates", L"hours", std::to_wstring(std::clamp(updateHours, 1, 168)));
    put(L"updates", L"rules", feedRules ? L"1" : L"0");
    put(L"updates", L"bazaar", feedBazaar ? L"1" : L"0");
    put(L"schedule", L"enabled", schedule.enabled ? L"1" : L"0");
    put(L"schedule", L"type", schedule.type == "full" ? L"full" : L"quick");
    put(L"schedule", L"frequency", schedule.frequency == "weekly" ? L"weekly" : L"daily");
    put(L"schedule", L"hour", std::to_wstring(std::clamp(schedule.hour, 0, 23)));
    put(L"schedule", L"minute", std::to_wstring(std::clamp(schedule.minute, 0, 59)));
    put(L"schedule", L"weekday", std::to_wstring(std::clamp(schedule.weekday, 0, 6)));
    put(L"service", L"cpu_percent", std::to_wstring(std::clamp(cpuPercent, 10, 100)));

    WritePrivateProfileStringW(L"exclusions", nullptr, nullptr, f.c_str()); // borra la sección anterior
    put(L"exclusions", L"count", std::to_wstring(exclusions.size()));
    for (size_t i = 0; i < exclusions.size(); ++i) {
        put(L"exclusions", (L"path" + std::to_wstring(i)).c_str(), exclusions[i].wstring());
    }
    return ok;
}

// ----------------------------------------------------------------------------- programación

namespace {

bool toLocal(std::time_t t, std::tm& out) { return localtime_s(&out, &t) == 0; }

/// Retrocede/avanza un número de días conservando la hora local (mktime normaliza DST y fin de mes).
std::time_t shiftDays(std::time_t t, int days) {
    std::tm tm{};
    if (!toLocal(t, tm)) return t;
    tm.tm_mday += days;
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

} // namespace

std::time_t scheduleLastDue(const ScanSchedule& s, std::time_t now) {
    if (!s.enabled) return 0;

    std::tm tm{};
    if (!toLocal(now, tm)) return 0;
    tm.tm_hour = std::clamp(s.hour, 0, 23);
    tm.tm_min = std::clamp(s.minute, 0, 59);
    tm.tm_sec = 0;
    tm.tm_isdst = -1;
    std::time_t t = std::mktime(&tm);
    if (t == static_cast<std::time_t>(-1)) return 0;
    if (t > now) t = shiftDays(t, -1);

    if (s.frequency == "weekly") {
        for (int i = 0; i < 7; ++i) {
            std::tm w{};
            toLocal(t, w);
            if (w.tm_wday == std::clamp(s.weekday, 0, 6)) break;
            t = shiftDays(t, -1);
        }
    }
    return t;
}

bool scheduleIsDue(const ScanSchedule& s, std::time_t now, std::time_t lastRun) {
    const std::time_t due = scheduleLastDue(s, now);
    return due != 0 && lastRun < due;
}

std::time_t scheduleNextRun(const ScanSchedule& s, std::time_t now) {
    const std::time_t last = scheduleLastDue(s, now);
    if (last == 0) return 0;
    std::time_t next = shiftDays(last, s.frequency == "weekly" ? 7 : 1);
    while (next <= now) next = shiftDays(next, s.frequency == "weekly" ? 7 : 1);
    return next;
}

std::string formatLocalStamp(std::time_t t) {
    std::tm tm{};
    if (t == 0 || !toLocal(t, tm)) return {};
    char buf[24]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

std::time_t parseLocalStamp(const std::string& text) {
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (std::sscanf(text.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &se) < 5 || y < 1970) return 0;
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = se;
    tm.tm_isdst = -1;
    const std::time_t t = std::mktime(&tm);
    return t == static_cast<std::time_t>(-1) ? 0 : t;
}

size_t ProtectionSettings::threadCount() const {
    const size_t cores = std::max<size_t>(1, std::thread::hardware_concurrency());
    const int pct = std::clamp(cpuPercent, 10, 100);
    return std::max<size_t>(1, cores * static_cast<size_t>(pct) / 100);
}

bool ProtectionSettings::isExcluded(const std::filesystem::path& p) const {
    if (exclusions.empty()) return false;
    const std::wstring target = normalizedLower(p);
    for (const auto& ex : exclusions) {
        const std::wstring e = normalizedLower(ex);
        if (e.empty()) continue;
        if (target == e) return true;
        if (target.size() > e.size() && target.compare(0, e.size(), e) == 0 && target[e.size()] == L'\\') return true;
    }
    return false;
}

} // namespace openguard
