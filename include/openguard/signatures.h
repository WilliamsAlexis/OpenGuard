/**
 * @file signatures.h
 * @brief Gestor de base de datos SQLite para firmas criptográficas de malware.
 * @details Proporciona almacenamiento indexado en B-Tree para consultas ultra rápidas
 *          por SHA-256, SHA-1 y MD5 con soporte de transacciones seguras y concurrencia.
 */

#pragma once

#include "openguard/types.h"
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <mutex>
#include <memory>

struct sqlite3;

namespace openguard {

/**
 * @struct SignatureRecord
 * @brief Representa un registro individual de firma almacenado en la base de datos.
 */
struct SignatureRecord {
    int id{0};                          ///< Identificador primario autonumérico.
    std::string sha256;                 ///< Hash SHA-256 en minúsculas.
    std::string sha1;                   ///< Hash SHA-1 en minúsculas.
    std::string md5;                    ///< Hash MD5 en minúsculas.
    std::string malwareName;            ///< Nombre del malware o familia detectada.
    std::string threatType{"unknown"};  ///< Clasificación (trojan, ransomware, miner, test).
    std::string severity{"high"};       ///< Nivel de riesgo (low, medium, high, critical).
    std::string source{"openguard"};    ///< Origen de la firma (repositorio, eicar, local).
};

/**
 * @struct SignatureStats
 * @brief Resumen estadístico del contenido actual de la base de datos de firmas.
 */
struct SignatureStats {
    size_t totalSignatures{0};                      ///< Conteo total de firmas registradas.
    std::vector<std::pair<std::string, size_t>> bySeverity; ///< Conteo agrupado por severidad.
    std::vector<std::pair<std::string, size_t>> byType;     ///< Conteo agrupado por categoría de amenaza.
};

/**
 * @class SignatureDB
 * @brief Administrador seguro y protegido por exclusión mutua de la base de datos SQLite de firmas.
 */
class SignatureDB {
public:
    /**
     * @brief Construye el gestor y abre o inicializa la base de datos en la ruta indicada.
     * @param dbPath Ruta al archivo SQLite (ej: "signatures/hashes.db").
     */
    explicit SignatureDB(const std::filesystem::path& dbPath);

    /**
     * @brief Destructor que cierra de forma ordenada las conexiones abiertas con SQLite.
     */
    ~SignatureDB();

    // Deshabilitar copia para prevenir estados inconsistentes de descriptores
    SignatureDB(const SignatureDB&) = delete;
    SignatureDB& operator=(const SignatureDB&) = delete;

    /**
     * @brief Busca si alguno de los hashes provistos coincide con una firma maliciosa conocida.
     * @details Prioridad de consulta: SHA-256 > SHA-1 > MD5.
     * @param sha256 Hash SHA-256 del archivo analizado.
     * @param sha1 Hash SHA-1 del archivo analizado.
     * @param md5 Hash MD5 del archivo analizado.
     * @return SignatureRecord si existe coincidencia; std::nullopt si el archivo no está catalogado.
     */
    [[nodiscard]] std::optional<SignatureRecord> lookup(
        const std::string& sha256,
        const std::string& sha1 = "",
        const std::string& md5 = ""
    );

    /**
     * @brief Agrega una nueva firma individual a la base de datos de manera atómica.
     * @param record Estructura con los datos de la firma a insertar.
     * @return true si fue insertada con éxito; false si ya existía o hubo error de I/O.
     */
    bool addSignature(const SignatureRecord& record);

    /**
     * @brief Realiza la importación masiva de un lote de firmas dentro de una única transacción.
     * @param records Vector de firmas a insertar.
     * @param[out] inserted Cantidad de firmas nuevas insertadas con éxito.
     * @param[out] skipped Cantidad de firmas omitidas por estar duplicadas o malformadas.
     * @return true si la transacción se confirmó exitosamente; false en caso de rollback.
     */
    bool bulkImport(const std::vector<SignatureRecord>& records,
                    size_t& inserted,
                    size_t& skipped);

    /**
     * @brief Importa firmas desde un archivo JSON con el formato de signatures/hashes_index.json.
     * @details Los registros con hashes malformados se descartan sin abortar la importación.
     *          Es idempotente: las firmas ya presentes se omiten.
     * @param jsonPath Ruta del archivo JSON.
     * @param[out] inserted Firmas nuevas insertadas.
     * @param[out] skipped Firmas descartadas por duplicadas o inválidas.
     * @return true si el archivo fue procesado; false si no existe, es inválido o la base es de solo lectura.
     */
    bool importFromJson(const std::filesystem::path& jsonPath, size_t& inserted, size_t& skipped);

    /**
     * @brief Importa una lista de hashes en texto plano (uno por línea; SHA-256, SHA-1 o MD5; "#" = comentario).
     * @param text Contenido de la lista.
     * @param malwareName Nombre de detección asignado a todos los hashes de la lista.
     * @param source Origen registrado (ej: "bazaar").
     * @param[out] inserted Hashes nuevos.
     * @param[out] skipped Líneas inválidas o duplicadas.
     */
    bool importHashList(const std::string& text, const std::string& malwareName, const std::string& source,
                        size_t& inserted, size_t& skipped);

    /**
     * @brief Inserta las firmas estándar de prueba EICAR para verificación defensiva inofensiva.
     */
    void seedEicar();

    /**
     * @brief Indica si la base se abrió en modo solo lectura (usuario sin permisos de escritura).
     */
    [[nodiscard]] bool isReadOnly() const noexcept { return m_readOnly; }

    /**
     * @brief Obtiene las métricas cuantitativas actuales de la base de datos.
     * @return Estructura SignatureStats con los totales.
     */
    [[nodiscard]] SignatureStats getStats();

    /**
     * @brief Verifica si la base de datos SQLite fue abierta y está lista para operar.
     * @return true si la conexión está activa; false en caso de fallo.
     */
    [[nodiscard]] bool isOpen() const noexcept;

private:
    /**
     * @brief Crea las tablas e índices B-Tree si no existen previamente.
     */
    void initializeSchema();

    std::filesystem::path m_dbPath;
    sqlite3* m_dbHandle{nullptr};
    mutable std::mutex m_mutex;
    bool m_initialized{false};
    bool m_readOnly{false};
};

} // namespace openguard

