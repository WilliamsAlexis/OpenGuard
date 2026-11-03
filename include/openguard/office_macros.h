/**
 * @file office_macros.h
 * @brief Detección estática de macros VBA en documentos de Microsoft Office (sin abrir ni ejecutar nada).
 * @details Cubre formatos OLE antiguos (.doc, .xls, .ppt) buscando el almacenamiento "_VBA_PROJECT" y palabras
 *          clave de ejecución automática y de comportamiento sospechoso; y OOXML (.docm, .xlsm...) detectando la
 *          entrada "vbaProject.bin" del contenedor ZIP. Limitación: el código VBA va comprimido (MS-OVBA) y las
 *          entradas ZIP van comprimidas con Deflate, por lo que el contenido se ve de forma parcial; la presencia
 *          de macros sí se detecta de forma fiable.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace openguard {

struct MacroReport {
    bool isOfficeFormat{false};            ///< La extensión corresponde a un documento Office.
    bool hasMacros{false};                 ///< Contiene un proyecto VBA.
    bool autoExec{false};                  ///< Contiene un disparador de ejecución automática (AutoOpen, ...).
    std::vector<std::string> suspicious;   ///< Palabras clave sospechosas halladas (Shell, powershell, ...).
    std::vector<std::string> findings;     ///< Descripciones legibles de los hallazgos.
    int score{0};                          ///< Riesgo 0-100.
};

/// Extensiones tratadas como documentos Office (minúsculas, con punto).
[[nodiscard]] bool isOfficeExtension(const std::string& lowerExt);

/**
 * @brief Analiza el contenido de un documento Office ya cargado en memoria.
 * @param data Contenido (se inspeccionan como máximo los primeros 8 MB).
 * @param lowerExt Extensión en minúsculas con punto, p. ej. ".docm".
 */
[[nodiscard]] MacroReport analyzeOfficeMacros(const uint8_t* data, size_t size, const std::string& lowerExt);

} // namespace openguard
