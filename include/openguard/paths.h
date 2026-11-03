/**
 * @file paths.h
 * @brief Resolución centralizada de rutas de OpenGuard (instalación, datos, cuarentena, logs).
 * @details Evita depender del directorio de trabajo actual. Los datos mutables (base de firmas,
 *          cuarentena y registros) viven en %ProgramData%\OpenGuard, mientras que los recursos
 *          de solo lectura (firmas JSON, reglas) residen junto a los ejecutables.
 *          La variable de entorno OPENGUARD_DATA_DIR permite redirigir los datos (modo portátil / pruebas).
 */

#pragma once

#include <filesystem>
#include <string>

namespace openguard::paths {

/// Convierte una ruta a UTF-8 (necesario para SQLite y para imprimir en consola UTF-8).
[[nodiscard]] std::string toUtf8(const std::filesystem::path& p);

/// Convierte una cadena UTF-8 a ruta de Windows.
[[nodiscard]] std::filesystem::path fromUtf8(const std::string& s);

/// Directorio donde reside el ejecutable en curso.
[[nodiscard]] std::filesystem::path executableDir();

/// Directorio de datos mutables (se crea si no existe).
[[nodiscard]] std::filesystem::path dataDir();

/// Directorio con los recursos de firmas (hashes_index.json, reglas YARA).
[[nodiscard]] std::filesystem::path signaturesDir();

/// Base de datos SQLite de firmas.
[[nodiscard]] std::filesystem::path databasePath();

/// Directorio de la bóveda de cuarentena.
[[nodiscard]] std::filesystem::path quarantineDir();

/// Directorio de registros (se crea si no existe).
[[nodiscard]] std::filesystem::path logsDir();

} // namespace openguard::paths

namespace openguard::paths {

/// Extensión en minúsculas (con punto). Los caracteres no ASCII se sustituyen por '?', por lo que
/// nunca lanza excepciones (path::string() puede lanzarlas en MSVC con nombres no representables en ANSI).
[[nodiscard]] std::string extensionLower(const std::filesystem::path& p);

} // namespace openguard::paths
