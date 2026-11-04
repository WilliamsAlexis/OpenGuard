/**
 * @file cleaner.h
 * @brief Limpieza de archivos temporales y cachés seguras para liberar espacio.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace openguard::cleaner {

/// Una categoría de limpieza (un conjunto de carpetas con el mismo criterio).
struct Category {
    std::string id;                          ///< "user_temp", "windows_temp", "thumbnails", "crash_dumps", "browser_cache", "recycle_bin".
    std::wstring name;
    std::wstring description;
    bool defaultSelected{true};
    bool recycleBin{false};                  ///< Se vacía con la API del shell en lugar de borrar archivos.
    std::vector<std::filesystem::path> roots;///< Carpetas que se limpian (el contenido, nunca la carpeta raíz).
    std::wstring namePrefix;                 ///< Si no está vacío, solo se tocan archivos cuyo nombre empieza así.
    std::chrono::hours minAge{0};            ///< No se tocan archivos modificados hace menos de esto (evita borrar lo que está en uso).
};

struct Usage {
    size_t files{0};
    uint64_t bytes{0};
};

struct CleanResult {
    size_t deleted{0};
    uint64_t freed{0};
    size_t failed{0};                        ///< Archivos en uso o sin permisos (se dejan como están).
};

/// Categorías disponibles en este equipo (solo las que existen).
[[nodiscard]] std::vector<Category> categories();

/// Espacio que se liberaría con una categoría.
[[nodiscard]] Usage measure(const Category& c, const std::atomic<bool>* cancel = nullptr);

/// Limpia una categoría. No sigue enlaces simbólicos ni uniones (junction) y nunca borra la carpeta raíz.
CleanResult clean(const Category& c, const std::atomic<bool>* cancel = nullptr);

// Núcleo reutilizable (y probado) para una sola carpeta
[[nodiscard]] Usage measureDirectory(const std::filesystem::path& root, std::chrono::hours minAge,
                                     const std::wstring& namePrefix = {}, const std::atomic<bool>* cancel = nullptr);
CleanResult cleanDirectory(const std::filesystem::path& root, std::chrono::hours minAge,
                           const std::wstring& namePrefix = {}, const std::atomic<bool>* cancel = nullptr);

/// "1,2 GB", "340 MB"...
[[nodiscard]] std::wstring formatBytes(uint64_t bytes);

} // namespace openguard::cleaner
