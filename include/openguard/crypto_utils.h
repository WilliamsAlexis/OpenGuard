/**
 * @file crypto_utils.h
 * @brief Funciones criptográficas auxiliares utilizando la API nativa de Windows CNG (BCrypt).
 * @details Proporciona cálculo seguro de hashes (SHA-256, SHA-1, MD5) mediante lectura
 *          en bloques optimizados y manejo de excepciones RAII.
 */

#pragma once

#include <string>
#include <filesystem>
#include <vector>
#include <cstdint>

namespace openguard {

/**
 * @struct FileHashes
 * @brief Estructura que agrupa los tres hashes estándar calculados en una sola pasada de I/O.
 */
struct FileHashes {
    std::string sha256;     ///< Hash SHA-256 en formato hexadecimal en minúsculas.
    std::string sha1;       ///< Hash SHA-1 en formato hexadecimal en minúsculas.
    std::string md5;        ///< Hash MD5 en formato hexadecimal en minúsculas.
    bool success{false};    ///< Indica si la lectura y el cómputo se completaron con éxito.
};

/**
 * @class CryptoUtils
 * @brief Clase utilitaria estática para operaciones criptográficas seguras en Windows.
 */
class CryptoUtils {
public:
    /**
     * @brief Calcula simultáneamente SHA-256, SHA-1 y MD5 de un archivo en una sola pasada de disco.
     * @param filePath Ruta del archivo a examinar (soporta rutas largas \\?\).
     * @param chunkSize Tamaño del búfer de lectura en bytes (por defecto 64 KB = 65536).
     * @return Estructura FileHashes con los resultados.
     */
    static FileHashes computeFileHashes(const std::filesystem::path& filePath,
                                        size_t chunkSize = 65536);

    /**
     * @brief Calcula exclusivamente el hash SHA-256 de un archivo en disco.
     * @param filePath Ruta del archivo.
     * @return Cadena con el hash en hexadecimal (64 caracteres) o cadena vacía si hay error.
     */
    static std::string computeSha256(const std::filesystem::path& filePath);

    /**
     * @brief Calcula el hash SHA-256 de un búfer de memoria existente.
     * @param data Puntero al búfer de bytes.
     * @param size Longitud del búfer en bytes.
     * @return Cadena con el hash en hexadecimal.
     */
    static std::string computeSha256FromBuffer(const void* data, size_t size);

    /**
     * @brief Verifica si el contenido de un archivo coincide con un hash SHA-256 esperado.
     * @param filePath Ruta del archivo.
     * @param expectedSha256 Hash esperado en hexadecimal (ignora mayúsculas/minúsculas).
     * @return true si coincide exactamente; false en caso de discrepancia o error de lectura.
     */
    static bool verifyIntegrity(const std::filesystem::path& filePath,
                                const std::string& expectedSha256);
};

} // namespace openguard

