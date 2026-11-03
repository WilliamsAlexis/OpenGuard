/**
 * @file yara_lite.h
 * @brief Intérprete embebido de un subconjunto de reglas YARA (sin dependencias externas).
 * @details Soporta lo que usan las reglas de signatures/yara_rules:
 *          - strings de texto (modificadores: nocase, ascii, wide, fullword),
 *          - strings hexadecimales (bytes y comodín "??"),
 *          - strings de expresión regular /.../ (ECMAScript, flag nocase),
 *          - condiciones: and / or / not, paréntesis, $id, "N of them", "any|all of them",
 *            "N of ($a, $b, $c)" (con prefijos "$a*"), filesize con KB/MB, true/false.
 *          Las construcciones no soportadas (módulos, saltos [n-m], etc.) hacen que la regla se
 *          descarte en la carga (se informa en el contador de omitidas), nunca que produzca falsos positivos.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace openguard {

/// Una regla que coincidió con el contenido analizado.
struct YaraMatch {
    std::string rule;         ///< Nombre de la regla.
    std::string severity;     ///< "low" | "medium" | "high" | "critical" (meta severity).
    std::string description;  ///< meta description.
    std::string family;       ///< meta malware_family.
};

/**
 * @class YaraLite
 * @brief Conjunto de reglas cargadas y motor de evaluación (thread-safe en lectura).
 */
class YaraLite {
public:
    YaraLite();
    ~YaraLite();
    YaraLite(YaraLite&&) noexcept;
    YaraLite& operator=(YaraLite&&) noexcept;
    YaraLite(const YaraLite&) = delete;
    YaraLite& operator=(const YaraLite&) = delete;

    /// Carga todas las reglas *.yar de un directorio. @return reglas cargadas.
    size_t loadDirectory(const std::filesystem::path& dir);

    /// Carga las reglas de baseDir y de overrideDir; si un archivo existe en ambas, solo vale el de overrideDir.
    size_t loadDirectories(const std::filesystem::path& baseDir, const std::filesystem::path& overrideDir);

    /// Carga las reglas de un archivo. @return reglas cargadas.
    size_t loadFile(const std::filesystem::path& file);

    /// Carga las reglas desde texto. @return reglas cargadas.
    size_t loadFromString(const std::string& source);

    /// Reglas cargadas correctamente.
    [[nodiscard]] size_t ruleCount() const noexcept;

    /// Reglas descartadas por usar construcciones no soportadas o ser inválidas.
    [[nodiscard]] size_t skippedCount() const noexcept;

    /// Evalúa todas las reglas sobre un búfer. No modifica el estado: puede llamarse en paralelo.
    [[nodiscard]] std::vector<YaraMatch> scan(const uint8_t* data, size_t size) const;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace openguard
