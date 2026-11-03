/**
 * @file settings.h
 * @brief Configuración de protección compartida por servicio, GUI y CLI (config.ini en la carpeta de datos).
 * @details Una sola implementación de lectura/escritura evita que cada ejecutable interprete el archivo
 *          a su manera. Los valores ausentes toman los predeterminados (compatible hacia atrás).
 */

#pragma once

#include <cstddef>
#include <ctime>
#include <filesystem>
#include <string>
#include <vector>

namespace openguard {

/// Programación de análisis automáticos (la ejecuta el servicio).
struct ScanSchedule {
    bool enabled{false};
    std::string type{"quick"};         ///< "quick" | "full"
    std::string frequency{"daily"};    ///< "daily" | "weekly"
    int hour{12};                      ///< 0-23 (hora local)
    int minute{0};                     ///< 0-59
    int weekday{1};                    ///< 0 = domingo ... 6 = sábado (solo semanal)
};

/// Última hora programada que ya debió ejecutarse (<= now), o 0 si la programación está desactivada.
[[nodiscard]] std::time_t scheduleLastDue(const ScanSchedule& s, std::time_t now);

/// true si hay una ejecución programada pendiente: la última hora programada es posterior a la última ejecución.
/// Si el equipo estuvo apagado a la hora prevista, se ejecuta al volver a estar disponible (puesta al día).
[[nodiscard]] bool scheduleIsDue(const ScanSchedule& s, std::time_t now, std::time_t lastRun);

/// Próxima ejecución programada posterior a `now` (0 si está desactivada).
[[nodiscard]] std::time_t scheduleNextRun(const ScanSchedule& s, std::time_t now);

/// Formato "YYYY-MM-DD HH:MM:SS" en hora local, y su inverso (0 si el texto no es válido).
[[nodiscard]] std::string formatLocalStamp(std::time_t t);
[[nodiscard]] std::time_t parseLocalStamp(const std::string& text);

struct ProtectionSettings {
    bool autoQuarantine{true};     ///< Aislar automáticamente lo confirmado.
    bool decoys{true};             ///< Archivos señuelo anti-ransomware.
    bool scanUsb{true};            ///< Equivale a usbMode != "off" (se conserva por compatibilidad con versiones anteriores).
    /// Unidades externas: "ask" = la aplicación pregunta si permite el análisis; "auto" = el servicio las analiza
    /// sin preguntar; "off" = no se analizan. Si en modo "ask" la aplicación no está abierta, el servicio las analiza.
    std::string usbMode{"ask"};
    bool scanDownloads{true};      ///< Analizar automáticamente los archivos que se descargan (carpetas Descargas).
    bool isolatedScan{true};       ///< Analizar el contenido en un proceso aislado de bajo privilegio.
    // Actualización automática de firmas y reglas
    bool autoUpdate{true};         ///< Comprobar fuentes de forma periódica (servicio).
    int updateHours{6};            ///< Intervalo entre comprobaciones (1-168).
    bool feedRules{true};          ///< Reglas YARA oficiales (firmadas).
    bool feedBazaar{false};        ///< MalwareBazaar (requiere clave de abuse.ch guardada en el SecretStore).
    ScanSchedule schedule;         ///< Análisis programado.
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
