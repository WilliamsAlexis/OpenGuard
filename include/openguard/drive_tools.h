/**
 * @file drive_tools.h
 * @brief Inspección y reparación de unidades externas (USB, tarjetas, discos portátiles).
 * @details Reconoce los síntomas de las infecciones más comunes en medios extraíbles, sin ejecutar nada:
 *            - autorun.inf que lanza programas al conectar la unidad,
 *            - "virus de accesos directos": carpetas y archivos ocultos en la raíz y accesos directos (.lnk) o
 *              ejecutables con su mismo nombre que los reemplazan,
 *            - accesos directos que invocan intérpretes (cmd, wscript, powershell...).
 *          La reparación restaura la visibilidad de los archivos del usuario y elimina los accesos directos y el
 *          autorun maliciosos. No toca ejecutables sospechosos: esos los trata el análisis (aislamiento en cuarentena).
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace openguard {

struct DriveFinding {
    std::string code;                  ///< "autorun" | "hidden" | "shortcut_virus" | "lnk_suspicious" | "exe_lookalike"
    std::string description;           ///< Texto legible para el usuario.
    std::filesystem::path path;
};

struct DriveInspection {
    std::filesystem::path root;
    std::vector<DriveFinding> findings;
    size_t hiddenItems{0};             ///< Elementos ocultos del usuario en la raíz (sin contar los del sistema).
    bool hasAutorun{false};            ///< autorun.inf que lanza programas.
    bool shortcutVirusSuspected{false};///< Patrón de accesos directos falsos / carpetas ocultas.

    /// true si hay algo que la reparación pueda corregir.
    [[nodiscard]] bool needsRepair() const { return !findings.empty(); }
};

struct RepairResult {
    size_t unhidden{0};
    size_t removedShortcuts{0};
    size_t removedAutorun{0};
    size_t failed{0};
    std::vector<std::string> log;
};

/// Examina la raíz de una unidad (solo lectura; no sigue ni abre ejecutables).
[[nodiscard]] DriveInspection inspectDrive(const std::filesystem::path& root);

/**
 * @brief Repara los síntomas encontrados: elimina el autorun malicioso y los accesos directos falsos, y quita los
 *        atributos oculto/sistema de los archivos y carpetas del usuario cuando hay indicios de ocultación.
 */
RepairResult repairDrive(const DriveInspection& inspection);

} // namespace openguard
