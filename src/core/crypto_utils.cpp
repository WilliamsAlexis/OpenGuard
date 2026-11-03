/**
 * @file crypto_utils.cpp
 * @brief Implementación de funciones criptográficas utilizando la API BCrypt de Windows CNG.
 * @details Este módulo implementa el cálculo de hashes en una sola pasada de lectura por bloques,
 *          garantizando bajo uso de memoria RAM y velocidad nativa en sistemas Windows 10 y 11.
 */

#include "openguard/crypto_utils.h"

#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace openguard {

namespace {

/**
 * @class ScopedBCryptAlg
 * @brief Envoltura RAII para gestionar el ciclo de vida de un proveedor de algoritmos BCrypt.
 */
class ScopedBCryptAlg {
public:
    /**
     * @brief Abre un proveedor de algoritmo criptográfico de Windows.
     * @param algId Identificador del algoritmo (ej: BCRYPT_SHA256_ALGORITHM).
     */
    explicit ScopedBCryptAlg(LPCWSTR algId) {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&m_handle, algId, nullptr, 0);
        if (!NT_SUCCESS(status)) {
            m_handle = nullptr;
        }
    }

    /**
     * @brief Destructor que libera el proveedor de forma segura.
     */
    ~ScopedBCryptAlg() {
        if (m_handle) {
            BCryptCloseAlgorithmProvider(m_handle, 0);
            m_handle = nullptr;
        }
    }

    // Deshabilitar copias no deseadas
    ScopedBCryptAlg(const ScopedBCryptAlg&) = delete;
    ScopedBCryptAlg& operator=(const ScopedBCryptAlg&) = delete;

    /**
     * @brief Obtiene el manejador nativo del algoritmo.
     * @return BCRYPT_ALG_HANDLE válido o nullptr.
     */
    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return m_handle; }

    /**
     * @brief Verifica si el proveedor se inicializó correctamente.
     * @return true si el manejador es válido; false en caso de error.
     */
    [[nodiscard]] bool isValid() const noexcept { return m_handle != nullptr; }

private:
    BCRYPT_ALG_HANDLE m_handle{nullptr};
};

/**
 * @class ScopedBCryptHash
 * @brief Envoltura RAII para el estado de cálculo de un hash en BCrypt.
 */
class ScopedBCryptHash {
public:
    /**
     * @brief Inicializa el objeto hash a partir de un proveedor de algoritmos.
     * @param algHandle Manejador del proveedor de algoritmos activo.
     */
    explicit ScopedBCryptHash(BCRYPT_ALG_HANDLE algHandle) {
        if (!algHandle) return;

        DWORD hashObjSize = 0;
        DWORD bytesCopied = 0;
        NTSTATUS status = BCryptGetProperty(
            algHandle,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PBYTE>(&hashObjSize),
            sizeof(DWORD),
            &bytesCopied,
            0
        );

        if (!NT_SUCCESS(status) || hashObjSize == 0) return;

        m_hashObject.resize(hashObjSize);
        status = BCryptCreateHash(
            algHandle,
            &m_hashHandle,
            m_hashObject.data(),
            hashObjSize,
            nullptr,
            0,
            0
        );

        if (!NT_SUCCESS(status)) {
            m_hashHandle = nullptr;
            return;
        }

        DWORD hashLen = 0;
        status = BCryptGetProperty(
            algHandle,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PBYTE>(&hashLen),
            sizeof(DWORD),
            &bytesCopied,
            0
        );

        if (NT_SUCCESS(status) && hashLen > 0) {
            m_hashLength = hashLen;
            m_valid = true;
        }
    }

    /**
     * @brief Destructor que destruye el hash activo.
     */
    ~ScopedBCryptHash() {
        if (m_hashHandle) {
            BCryptDestroyHash(m_hashHandle);
            m_hashHandle = nullptr;
        }
    }

    // Deshabilitar copias
    ScopedBCryptHash(const ScopedBCryptHash&) = delete;
    ScopedBCryptHash& operator=(const ScopedBCryptHash&) = delete;

    /**
     * @brief Alimenta el cálculo criptográfico con un bloque de bytes.
     * @param data Puntero al búfer de entrada.
     * @param size Longitud de los datos a procesar en bytes.
     * @return true si la operación fue exitosa; false en caso contrario.
     */
    bool update(const void* data, size_t size) {
        if (!m_valid || !m_hashHandle || size == 0) return m_valid;
        NTSTATUS status = BCryptHashData(
            m_hashHandle,
            reinterpret_cast<PBYTE>(const_cast<void*>(data)),
            static_cast<ULONG>(size),
            0
        );
        return NT_SUCCESS(status);
    }

    /**
     * @brief Finaliza el hash y devuelve el resultado en cadena hexadecimal.
     * @return Cadena hexadecimal en minúsculas del hash calculado.
     */
    std::string finalize() {
        if (!m_valid || !m_hashHandle || m_hashLength == 0) return "";

        std::vector<BYTE> digest(m_hashLength);
        NTSTATUS status = BCryptFinishHash(
            m_hashHandle,
            digest.data(),
            m_hashLength,
            0
        );

        if (!NT_SUCCESS(status)) return "";

        std::ostringstream oss;
        for (BYTE b : digest) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }

    /**
     * @brief Verifica si el objeto hash está en estado operativo.
     * @return true si está listo; false en caso de error.
     */
    [[nodiscard]] bool isValid() const noexcept { return m_valid; }

private:
    BCRYPT_HASH_HANDLE m_hashHandle{nullptr};
    std::vector<BYTE> m_hashObject;
    DWORD m_hashLength{0};
    bool m_valid{false};
};

} // namespace anónimo

FileHashes CryptoUtils::computeFileHashes(const std::filesystem::path& filePath, size_t chunkSize) {
    FileHashes result;

    // Inicializar proveedores de algoritmos para SHA-256, SHA-1 y MD5
    ScopedBCryptAlg algSha256(BCRYPT_SHA256_ALGORITHM);
    ScopedBCryptAlg algSha1(BCRYPT_SHA1_ALGORITHM);
    ScopedBCryptAlg algMd5(BCRYPT_MD5_ALGORITHM);

    if (!algSha256.isValid() || !algSha1.isValid() || !algMd5.isValid()) {
        return result;
    }

    ScopedBCryptHash hash256(algSha256.get());
    ScopedBCryptHash hash1(algSha1.get());
    ScopedBCryptHash hashMd5(algMd5.get());

    if (!hash256.isValid() || !hash1.isValid() || !hashMd5.isValid()) {
        return result;
    }

    // Apertura en modo binario utilizando la ruta nativa de Windows (soporta \\?\)
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return result;
    }

    std::vector<char> buffer(chunkSize > 0 ? chunkSize : 65536);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        std::streamsize bytesRead = file.gcount();
        if (bytesRead <= 0) break;

        hash256.update(buffer.data(), static_cast<size_t>(bytesRead));
        hash1.update(buffer.data(), static_cast<size_t>(bytesRead));
        hashMd5.update(buffer.data(), static_cast<size_t>(bytesRead));
    }

    result.sha256 = hash256.finalize();
    result.sha1 = hash1.finalize();
    result.md5 = hashMd5.finalize();
    result.success = !result.sha256.empty() && !result.sha1.empty() && !result.md5.empty();

    return result;
}

std::string CryptoUtils::computeSha256(const std::filesystem::path& filePath) {
    ScopedBCryptAlg algSha256(BCRYPT_SHA256_ALGORITHM);
    if (!algSha256.isValid()) return "";

    ScopedBCryptHash hash256(algSha256.get());
    if (!hash256.isValid()) return "";

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    std::vector<char> buffer(65536);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        std::streamsize bytesRead = file.gcount();
        if (bytesRead <= 0) break;
        hash256.update(buffer.data(), static_cast<size_t>(bytesRead));
    }

    return hash256.finalize();
}

std::string CryptoUtils::computeSha256FromBuffer(const void* data, size_t size) {
    if (!data || size == 0) return "";

    ScopedBCryptAlg algSha256(BCRYPT_SHA256_ALGORITHM);
    if (!algSha256.isValid()) return "";

    ScopedBCryptHash hash256(algSha256.get());
    if (!hash256.isValid()) return "";

    hash256.update(data, size);
    return hash256.finalize();
}

bool CryptoUtils::verifyIntegrity(const std::filesystem::path& filePath,
                                  const std::string& expectedSha256) {
    std::string actual = computeSha256(filePath);
    if (actual.empty()) return false;

    std::string expectedNorm = expectedSha256;
    std::transform(expectedNorm.begin(), expectedNorm.end(), expectedNorm.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return actual == expectedNorm;
}

} // namespace openguard

