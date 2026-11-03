/**
 * @file settings.h
 * @brief Configuración de protección compartida por servicio, GUI y CLI (config.ini en la carpeta de datos).
 * @details Una sola implementación de lectura/escritura evita que cada ejecutable interprete el archivo
 *          a su manera. Los valores ausentes toman los predeterminados (compatible hacia atrás).
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <vector>

namespace openguard {

struct ProtectionSettings {
    bool autoQuarantine{true};     ///< Aislar automáticamente lo confirmado.
    bool decoys{true};             ///< Archivos señuelo anti-ransomware.
    bool scanUsb{true};            ///< Analizar unidades USB al conectarlas.
    bool isolatedScan{true};       ///< Analizar el contenido en un proceso aislado de bajo privilegio.
    int cpuPercent{50};            ///< Límite de CPU para análisis (10-100): fracción de núcleos usada.
    std::vector<std::filesystem::path> exclusions; ///< Carpetas o archivos que no se analizan.

    /// Carga desde %ProgramData%\OpenGuard\config.ini (o el directorio indicado).
    [[nodiscard]] static ProtectionSettings load(const std::filesystem::path& iniPath = {});

    /// Guarda en el .ini. @return false si no hay permiso de escritura.
    bool save(const std::filesystem::path& iniPath = {}) const;

    /// Hilos de análisis resultantes del límite de CPU (mínimo 1).
    [[nodiscard]] size_t threadCount() const;

    /// Indica si una ruta cae dentro de alguna exclusión (comparación sin distinguir mayúsculas).
    [[nodiscard]] bool isExcluded(const std::filesystem::path& p) const;
};

} // namespace openguard
