/**
 * @file scanner.h
 * @brief Motor de escaneo multihilo de archivos y directorios para OpenGuard.
 * @details Integra verificación criptográfica por firmas (SHA-256/SHA-1/MD5),
 *          análisis de doble extensión, control de permisos de acceso en Windows
 *          y paralelismo mediante ThreadPool.
 */

#pragma once

#include "openguard/types.h"
#include "openguard/signatures.h"
#include "openguard/thread_pool.h"
#include "openguard/heuristics.h"
#include "openguard/yara_lite.h"

#include <filesystem>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>

namespace openguard {

/**
 * @struct ScannerConfig
 * @brief Parámetros de configuración operativa del escáner.
 */
struct ScannerConfig {
    size_t maxFileSizeBytes{256 * 1024 * 1024}; ///< Límite máximo de archivo a hashear (256 MB).
    size_t bufferSizeBytes{65536};              ///< Tamaño del bloque de lectura en bytes (64 KB).
    size_t threadCount{0};                      ///< Hilos concurrentes (0 = automático).
    bool lowPriority{false};                    ///< Hilos de análisis con prioridad inferior a la normal.
    bool checkDoubleExtensions{true};           ///< Activar heurística de doble extensión sospechosa.
    bool keepCleanResults{false};               ///< Conservar en la sesión también los archivos limpios (consume memoria en escaneos grandes).
    std::vector<std::filesystem::path> excludedPaths; ///< Directorios que se omiten en escaneos recursivos (ej: la cuarentena).
    std::filesystem::path yaraRulesDir;         ///< Carpeta con reglas *.yar (vacía = motor YARA desactivado).
    /// Si se define, scanFile() delega en este analizador (p. ej. el proceso aislado del servicio).
    std::function<ScanResult(const std::filesystem::path&)> customAnalyzer;
};

/**
 * @class FileScanner
 * @brief Orquestador del análisis de archivos en el sistema de almacenamiento.
 */
class FileScanner {
public:
    /**
     * @brief Construye el motor de escaneo asociándolo a la base de datos de firmas.
     * @param sigDb Puntero compartido al gestor de firmas SQLite.
     * @param config Configuración opcional del escáner.
     */
    explicit FileScanner(std::shared_ptr<SignatureDB> sigDb,
                         ScannerConfig config = ScannerConfig{});

    /**
     * @brief Destructor del escáner.
     */
    ~FileScanner() = default;

    /**
     * @brief Analiza un único archivo individual calculando sus hashes y cotejando firmas.
     * @param filePath Ruta del archivo en disco.
     * @return Estructura ScanResult con el diagnóstico y nivel de riesgo.
     */
    [[nodiscard]] ScanResult scanFile(const std::filesystem::path& filePath);

    /**
     * @brief Escanea de forma recursiva una ruta o directorio utilizando el pool de hilos.
     * @param targetPath Ruta raíz a explorar.
     * @param type Tipo de escaneo (Quick, Full, Custom, USB).
     * @param progressCallback Callback opcional invocado cada vez que finaliza un archivo.
     * @return ScanSessionStats con el resumen global de la sesión.
     */
    ScanSessionStats scanPath(
        const std::filesystem::path& targetPath,
        ScanType type = ScanType::Custom,
        std::function<void(const ScanResult&)> progressCallback = nullptr
    );

    /**
     * @brief Escanea una lista de rutas o unidades en paralelo.
     * @param targetPaths Colección de rutas a inspeccionar.
     * @param type Tipo de escaneo.
     * @param progressCallback Callback opcional para actualizaciones de progreso.
     * @return ScanSessionStats con el resumen consolidado.
     */
    ScanSessionStats scanPaths(
        const std::vector<std::filesystem::path>& targetPaths,
        ScanType type = ScanType::Custom,
        std::function<void(const ScanResult&)> progressCallback = nullptr
    );

    /**
     * @brief Enumera las unidades de disco fijas (HDD/SSD) del equipo, ej: "C:\\".
     * @return Raíces de las unidades fijas.
     */
    [[nodiscard]] static std::vector<std::filesystem::path> getFixedDrives();

    /// Convierte una coincidencia de la base de firmas en una amenaza confirmada (puntuación mínima 61).
    static void addSignatureMatch(ScanResult& result, const SignatureRecord& match);

    /// Detecta extensiones dobles engañosas (ej: "factura.pdf.exe").
    [[nodiscard]] static bool hasDoubleExtension(const std::filesystem::path& path);

    /**
     * @brief Detiene anticipadamente un escaneo en curso de forma segura.
     */
    void cancelScan() noexcept { m_cancelRequested = true; }

    /**
     * @brief Verifica si se solicitó la cancelación del escaneo activo.
     * @return true si se canceló; false si continúa la ejecución.
     */
    [[nodiscard]] bool isCancelled() const noexcept { return m_cancelRequested; }

    /// Cantidad de reglas YARA cargadas (0 si el motor está desactivado).
    [[nodiscard]] size_t yaraRuleCount() const noexcept { return m_yara ? m_yara->ruleCount() : 0; }

private:
    /**
     * @brief Evalúa heurísticamente si un archivo presenta extensiones engañosas (ej: "factura.pdf.exe").
     * @param path Ruta del archivo a examinar.
     * @return true si presenta patrón de doble extensión maliciosa; false en caso contrario.
     */
    std::shared_ptr<SignatureDB> m_sigDb;
    ScannerConfig m_config;
    std::unique_ptr<ThreadPool> m_threadPool;
    std::unique_ptr<HeuristicsEngine> m_heuristics;
    std::unique_ptr<YaraLite> m_yara;
    std::atomic<bool> m_cancelRequested{false};
};

} // namespace openguard

