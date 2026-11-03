/**
 * @file quarantine.h
 * @brief Bóveda de cuarentena segura cifrada con AES-256 (Windows CNG).
 * @details Aísla amenazas neutralizadas impidiendo cualquier ejecución involuntaria,
 *          gestiona el catálogo en SQLite y permite restaurar o eliminar de forma segura
 *          mediante sobrescritura de patrones aleatorios.
 */

#pragma once

#include "openguard/types.h"

#include <string>
#include <vector>
#include <filesystem>
#include <optional>
#include <mutex>
#include <memory>

struct sqlite3;

namespace openguard {

/**
 * @struct QuarantineItem
 * @brief Metadatos descriptivos de un elemento aislado dentro de la bóveda.
 */
struct QuarantineItem {
    std::string qid;                    ///< Identificador único del elemento (GUID o hash truncado).
    std::filesystem::path originalPath; ///< Ruta original de donde fue extraído el archivo.
    std::string threatName;             ///< Nombre de la amenaza diagnosticada.
    std::string severity;               ///< Nivel de riesgo original ("high", "critical", etc.).
    std::string sha256;                 ///< Hash SHA-256 del archivo original.
    std::string quarantinedAt;          ///< Fecha y hora de aislamiento en formato ISO-8601.
    size_t sizeBytes{0};                ///< Tamaño del archivo original en bytes.
    std::string encryptedFileName;      ///< Nombre del archivo cifrado en la bóveda (ej: "qid.qbin").
};

/**
 * @class QuarantineVault
 * @brief Gestor de cuarentena con cifrado simétrico AES-256 nativo de Windows.
 */
class QuarantineVault {
public:
    /**
     * @brief Construye la bóveda de cuarentena en el directorio especificado.
     * @param vaultDir Ruta al directorio que alojará la bóveda (por defecto "quarantine").
     */
    explicit QuarantineVault(const std::filesystem::path& vaultDir = "quarantine");

    /**
     * @brief Destructor de la bóveda.
     */
    ~QuarantineVault();

    QuarantineVault(const QuarantineVault&) = delete;
    QuarantineVault& operator=(const QuarantineVault&) = delete;

    /**
     * @brief Cifra y traslada un archivo malicioso a la bóveda de cuarentena.
     * @details Sobrescribe de forma segura el archivo original con bytes aleatorios antes de eliminarlo.
     * @param filePath Ruta del archivo a aislar.
     * @param threatName Nombre de la amenaza detectada.
     * @param severity Nivel de severidad asignado.
     * @param sha256 Hash SHA-256 del archivo (si está vacío, se calcula automáticamente).
     * @return std::optional con QuarantineItem si tuvo éxito; std::nullopt en caso de error.
     */
    std::optional<QuarantineItem> quarantineFile(
        const std::filesystem::path& filePath,
        const std::string& threatName = "Amenaza.Desconocida",
        const std::string& severity = "high",
        std::string sha256 = ""
    );

    /**
     * @brief Descifra y restaura un archivo aislado a su ruta original o a una alternativa.
     * @param qid Identificador único del elemento en cuarentena.
     * @param destinationPath Ruta destino opcional (si está vacía, se restaura a su ubicación original).
     * @return true si la restauración fue exitosa; false en caso contrario.
     */
    bool restoreFile(const std::string& qid,
                     const std::filesystem::path& destinationPath = {});

    /**
     * @brief Elimina permanentemente un elemento aislado y purga su entrada del catálogo.
     * @param qid Identificador del elemento a eliminar.
     * @return true si se borró con éxito; false si no existe o falló la eliminación.
     */
    bool deletePermanently(const std::string& qid);

    /**
     * @brief Lista todos los elementos actualmente resguardados en la cuarentena.
     * @return Vector de estructuras QuarantineItem.
     */
    [[nodiscard]] std::vector<QuarantineItem> listItems();

    /**
     * @brief Obtiene el total de elementos aislados en la bóveda.
     * @return Número de archivos en cuarentena.
     */
    [[nodiscard]] size_t getItemCount();

private:
    /**
     * @brief Carga o genera la clave criptográfica de la bóveda (256 bits).
     */
    void initializeKey();

    /**
     * @brief Inicializa la base de datos de metadatos de la cuarentena.
     */
    void initializeDatabase();

    /**
     * @brief Sobrescribe con datos aleatorios y elimina un archivo del disco de forma segura.
     * @param path Ruta del archivo a destruir.
     */
    static void secureDeleteFile(const std::filesystem::path& path) noexcept;

    std::filesystem::path m_vaultDir;
    std::filesystem::path m_filesDir;
    std::filesystem::path m_dbPath;
    std::filesystem::path m_keyPath;
    std::vector<uint8_t> m_aesKey;
    sqlite3* m_dbHandle{nullptr};
    mutable std::mutex m_mutex;
};

} // namespace openguard

