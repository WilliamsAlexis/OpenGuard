/**
 * @file settings.cpp
 * @brief Implementación de la configuración compartida de OpenGuard.
 */

#include "openguard/settings.h"
#include "openguard/paths.h"

#include <windows.h>

#include <algorithm>
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
    s.autoQuarantine = GetPrivateProfileIntW(L"service", L"auto_quarantine", 1, f.c_str()) != 0;
    s.decoys = GetPrivateProfileIntW(L"service", L"decoys", 1, f.c_str()) != 0;
    s.scanUsb = GetPrivateProfileIntW(L"service", L"scan_usb", 1, f.c_str()) != 0;
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
    put(L"service", L"auto_quarantine", autoQuarantine ? L"1" : L"0");
    put(L"service", L"decoys", decoys ? L"1" : L"0");
    put(L"service", L"scan_usb", scanUsb ? L"1" : L"0");
    put(L"service", L"cpu_percent", std::to_wstring(std::clamp(cpuPercent, 10, 100)));

    WritePrivateProfileStringW(L"exclusions", nullptr, nullptr, f.c_str()); // borra la sección anterior
    put(L"exclusions", L"count", std::to_wstring(exclusions.size()));
    for (size_t i = 0; i < exclusions.size(); ++i) {
        put(L"exclusions", (L"path" + std::to_wstring(i)).c_str(), exclusions[i].wstring());
    }
    return ok;
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
