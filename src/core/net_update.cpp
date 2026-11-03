/**
 * @file net_update.cpp
 * @brief Implementación de la descarga HTTPS con WinHTTP.
 */

#include "openguard/net_update.h"

#include <windows.h>
#include <winhttp.h>

#include <memory>
#include <vector>

#pragma comment(lib, "winhttp.lib")

#ifndef OPENGUARD_VERSION
#define OPENGUARD_VERSION "0.0"
#endif

namespace openguard::net {

namespace {

struct HInternetDeleter {
    void operator()(void* h) const { if (h) WinHttpCloseHandle(h); }
};
using HInternet = std::unique_ptr<void, HInternetDeleter>;

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

} // namespace

bool httpsGet(const std::string& url, std::string& body, std::string& error, size_t maxBytes, const std::string& authKey) {
    body.clear();
    error.clear();

    const std::wstring wurl = widen(url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwSchemeLength = uc.dwHostNameLength = uc.dwUrlPathLength = uc.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wurl.c_str(), static_cast<DWORD>(wurl.size()), 0, &uc)) {
        error = "URL invalida";
        return false;
    }
    if (uc.nScheme != INTERNET_SCHEME_HTTPS) {
        error = "Solo se permiten URLs https://";
        return false;
    }

    const std::wstring host(uc.lpszHostName, uc.dwHostNameLength);
    const std::wstring path = std::wstring(uc.lpszUrlPath, uc.dwUrlPathLength) +
                              std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength);

    const std::wstring agent = widen(std::string("OpenGuard/") + OPENGUARD_VERSION);
    HInternet session(WinHttpOpen(agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) { error = "No se pudo iniciar WinHTTP"; return false; }
    WinHttpSetTimeouts(session.get(), 15000, 15000, 30000, 60000);

    HInternet connect(WinHttpConnect(session.get(), host.c_str(), uc.nPort, 0));
    if (!connect) { error = "No se pudo conectar con el servidor"; return false; }

    HInternet request(WinHttpOpenRequest(connect.get(), L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!request) { error = "No se pudo crear la peticion"; return false; }

    std::wstring headers;
    if (!authKey.empty()) headers = L"Auth-Key: " + widen(authKey) + L"\r\n";

    if (!WinHttpSendRequest(request.get(), headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                            static_cast<DWORD>(headers.size()), WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.get(), nullptr)) {
        error = "Fallo de red o certificado TLS no valido (codigo " + std::to_string(GetLastError()) + ")";
        return false;
    }

    DWORD status = 0, size = sizeof(status);
    WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        error = "El servidor respondio HTTP " + std::to_string(status);
        return false;
    }

    std::vector<char> chunk(64 * 1024);
    for (;;) {
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), chunk.data(), static_cast<DWORD>(chunk.size()), &read)) {
            error = "Error leyendo la respuesta";
            return false;
        }
        if (read == 0) break;
        if (body.size() + read > maxBytes) {
            error = "La respuesta excede el tamano maximo permitido";
            body.clear();
            return false;
        }
        body.append(chunk.data(), read);
    }
    return true;
}

} // namespace openguard::net
