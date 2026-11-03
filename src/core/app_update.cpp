/**
 * @file app_update.cpp
 * @brief Implementación de la búsqueda y descarga de actualizaciones del programa.
 */

#include "openguard/app_update.h"
#include "openguard/crypto_utils.h"
#include "openguard/net_update.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <vector>

namespace openguard {

namespace {

std::vector<int> parseVersion(std::string v) {
    if (!v.empty() && (v[0] == 'v' || v[0] == 'V')) v.erase(0, 1);
    std::vector<int> parts;
    std::stringstream ss(v);
    std::string item;
    while (std::getline(ss, item, '.')) {
        size_t n = 0;
        while (n < item.size() && std::isdigit(static_cast<unsigned char>(item[n]))) ++n; // ignora sufijos como "-beta"
        try { parts.push_back(n ? std::stoi(item.substr(0, n)) : 0); } catch (...) { parts.push_back(0); }
    }
    while (parts.size() < 3) parts.push_back(0);
    return parts;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

bool isNewerVersion(const std::string& candidate, const std::string& current) {
    return parseVersion(candidate) > parseVersion(current);
}

AppUpdateInfo parseLatestRelease(const std::string& json, const std::string& currentVersion) {
    AppUpdateInfo info;

    nlohmann::json doc = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object()) {
        info.error = "Respuesta invalida del servidor de actualizaciones.";
        return info;
    }

    auto str = [&doc](const char* key) -> std::string {
        auto it = doc.find(key);
        return (it != doc.end() && it->is_string()) ? it->get<std::string>() : std::string();
    };

    const std::string tag = str("tag_name");
    if (tag.empty()) {
        info.error = "La Release no tiene etiqueta de version.";
        return info;
    }

    info.latestVersion = (tag[0] == 'v' || tag[0] == 'V') ? tag.substr(1) : tag;
    info.pageUrl = str("html_url");
    info.notes = str("body");
    if (info.notes.size() > 600) info.notes = info.notes.substr(0, 600) + "...";

    auto assets = doc.find("assets");
    if (assets != doc.end() && assets->is_array()) {
        for (const auto& a : *assets) {
            if (!a.is_object()) continue;
            const std::string name = a.value("name", std::string());
            const std::string url = a.value("browser_download_url", std::string());
            const std::string ln = lower(name);
            if (ln.size() > 4 && ln.compare(ln.size() - 4, 4, ".exe") == 0 && ln.find("setup") != std::string::npos) {
                info.installerUrl = url;
                info.installerName = name;
            } else if (ln.size() > 7 && ln.compare(ln.size() - 7, 7, ".sha256") == 0) {
                info.sha256Url = url;
            }
        }
    }

    info.ok = true;
    info.available = isNewerVersion(info.latestVersion, currentVersion);
    return info;
}

AppUpdateInfo checkForAppUpdate(const std::string& currentVersion, const std::string& repo) {
    std::string body, err;
    const std::string url = "https://api.github.com/repos/" + repo + "/releases/latest";
    if (!net::httpsGet(url, body, err, 2u * 1024u * 1024u)) {
        AppUpdateInfo info;
        info.error = err.find("404") != std::string::npos
            ? "Aun no hay versiones publicadas en GitHub."
            : err;
        return info;
    }
    return parseLatestRelease(body, currentVersion);
}

bool downloadInstaller(const AppUpdateInfo& info, const std::filesystem::path& destPath, std::string& error) {
    error.clear();
    if (info.installerUrl.empty()) {
        error = "La Release no incluye un instalador descargable.";
        return false;
    }

    std::string data;
    if (!net::httpsGet(info.installerUrl, data, error, 512u * 1024u * 1024u)) return false;
    if (data.size() < 64 * 1024 || data[0] != 'M' || data[1] != 'Z') {
        error = "El archivo descargado no es un instalador valido.";
        return false;
    }

    // Verificación de integridad con el .sha256 publicado (formato "hash  nombre")
    if (!info.sha256Url.empty()) {
        std::string shaText, shaErr;
        if (!net::httpsGet(info.sha256Url, shaText, shaErr, 4096)) {
            error = "No se pudo obtener el hash de verificacion: " + shaErr;
            return false;
        }
        std::string expected = lower(shaText.substr(0, shaText.find_first_of(" \t\r\n")));
        const std::string actual = CryptoUtils::computeSha256FromBuffer(data.data(), data.size());
        if (expected.size() != 64 || actual != expected) {
            error = "La verificacion SHA-256 fallo: el instalador descargado esta danado o fue alterado.";
            return false;
        }
    }

    std::ofstream out(destPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        error = "No se pudo guardar el instalador en disco.";
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out) {
        error = "Error al escribir el instalador.";
        return false;
    }
    return true;
}

} // namespace openguard
