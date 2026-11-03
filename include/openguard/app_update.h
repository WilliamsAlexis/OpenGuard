/**
 * @file app_update.h
 * @brief Búsqueda y descarga de nuevas versiones de OpenGuard desde las Releases de GitHub.
 * @details Solo hace peticiones GET por HTTPS a api.github.com y a la URL del instalador publicado.
 *          No envía información del equipo. La integridad del instalador se verifica con el
 *          archivo .sha256 que publica el workflow de CI junto a cada Release.
 */

#pragma once

#include <filesystem>
#include <string>

namespace openguard {

/// Repositorio consultado por defecto ("propietario/repositorio").
inline constexpr const char* kDefaultRepo = "WilliamsAlexis/OpenGuard";

struct AppUpdateInfo {
    bool ok{false};               ///< La consulta se completó.
    bool available{false};        ///< Hay una versión más reciente que la instalada.
    std::string latestVersion;    ///< Ej: "0.3.0".
    std::string pageUrl;          ///< Página de la Release.
    std::string installerUrl;     ///< URL del instalador (.exe) si existe.
    std::string installerName;    ///< Nombre del archivo del instalador.
    std::string sha256Url;        ///< URL del archivo .sha256 si existe.
    std::string notes;            ///< Notas de la versión (resumidas).
    std::string error;            ///< Motivo del fallo si ok == false.
};

/// Compara versiones "x.y.z" (admite prefijo "v"). @return true si candidate > current.
[[nodiscard]] bool isNewerVersion(const std::string& candidate, const std::string& current);

/// Interpreta la respuesta JSON de /releases/latest. Separada de la red para poder probarla.
[[nodiscard]] AppUpdateInfo parseLatestRelease(const std::string& json, const std::string& currentVersion);

/// Consulta la última Release publicada.
[[nodiscard]] AppUpdateInfo checkForAppUpdate(const std::string& currentVersion, const std::string& repo = kDefaultRepo);

/**
 * @brief Descarga el instalador a destPath y verifica su SHA-256 si la Release lo publica.
 * @return true si el archivo quedó descargado y verificado; en caso contrario `error` explica el motivo.
 */
bool downloadInstaller(const AppUpdateInfo& info, const std::filesystem::path& destPath, std::string& error);

} // namespace openguard
