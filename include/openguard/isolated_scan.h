/**
 * @file isolated_scan.h
 * @brief Análisis de archivos no confiables en un proceso trabajador aislado.
 * @details El servicio (SYSTEM) no debe parsear contenido hostil en su propio proceso: un fallo en el
 *          analizador de PE/YARA/scripts sería una escalada de privilegios. IsolatedScanner:
 *            1. abre el archivo en el servicio y se lo pasa al trabajador como HANDLE heredado de solo lectura
 *               (el trabajador no necesita acceso al sistema de archivos),
 *            2. lanza openguard_worker.exe con token restringido (sin privilegios, grupo Administradores
 *               deshabilitado) y nivel de integridad BAJO,
 *            3. lo encierra en un Job Object (límite de memoria, un único proceso, sin UI, se destruye al cerrar),
 *            4. aplica un tiempo máximo y trata un fallo o cuelgue del trabajador como un indicio sospechoso,
 *            5. completa lo que requiere servicios del sistema: base de firmas y firma Authenticode.
 *          Limitaciones (documentadas en el README): no usa AppContainer, por lo que no impide el acceso a la
 *          red del proceso trabajador; si no puede aplicarse el token restringido se degrada a Job Object solo.
 */

#pragma once

#include "openguard/signatures.h"
#include "openguard/types.h"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

namespace openguard {

class IsolatedScanner {
public:
    struct Options {
        std::filesystem::path workerExe;                    ///< Ruta de openguard_worker.exe.
        std::chrono::seconds timeout{60};                   ///< Tiempo máximo por archivo.
        size_t maxFileBytes{128u * 1024u * 1024u};          ///< Archivos mayores se omiten.
        size_t memoryLimitBytes{1024u * 1024u * 1024u};     ///< Límite de memoria del trabajador.
    };

    IsolatedScanner(std::shared_ptr<SignatureDB> db, Options options);

    /**
     * @brief Crea reglas del Firewall de Windows que bloquean TODO el tráfico (entrante y saliente) del
     *        ejecutable trabajador. Un trabajador comprometido por un archivo malicioso no podría exfiltrar
     *        datos ni descargar código. Requiere privilegios de administrador (el servicio los tiene).
     * @param[out] detail Descripción del fallo si devuelve false.
     */
    static bool ensureNetworkBlock(const std::filesystem::path& workerExe, std::string& detail);

    /// El ejecutable del trabajador existe y puede usarse.
    [[nodiscard]] bool available() const;

    /// true si alguna ejecución tuvo que degradarse (sin token restringido / integridad baja).
    [[nodiscard]] bool degraded() const noexcept { return m_degraded; }

    /**
     * @brief Analiza un archivo en el proceso aislado.
     * @return Resultado completo, o std::nullopt si el trabajador no pudo ni iniciarse (el llamador decide
     *         si usa un análisis en proceso como respaldo). Un trabajador que falla o se cuelga NO devuelve
     *         nullopt: se informa como amenaza heurística (Heuristic.AnalyzerFailure).
     */
    [[nodiscard]] std::optional<ScanResult> scan(const std::filesystem::path& file) const;

private:
    std::shared_ptr<SignatureDB> m_db;
    Options m_options;
    mutable std::atomic<bool> m_degraded{false};
};

} // namespace openguard
