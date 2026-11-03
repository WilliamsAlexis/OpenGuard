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
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

namespace openguard {

namespace {

/**
 * @class ScopedBCryptAlg
 * @brief Envoltura RAII para gestionar el ciclo de vida de un proveedor de algoritmos BCrypt.
 */
class ScopedBCryptAlg {
public:
    explicit ScopedBCryptAlg(LPCWSTR algId) {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&m_handle, algId, nullptr, 0);
        if (!NT_SUCCESS(status)) {
            m_handle = nullptr;
        }
    }

    ~ScopedBCryptAlg() {
        if (m_handle) {
            BCryptCloseAlgorithmProvider(m_handle, 0);
        }
    }

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool isValid() const noexcept { return m_handle != nullptr; }

    ScopedBCryptAlg(const ScopedBCryptAlg&) = delete;
    ScopedBCryptAlg& operator=(const ScopedBCryptAlg&) = delete;

private:
    BCRYPT_ALG_HANDLE m_handle{nullptr};
};

/**
 * @class ScopedBCryptHash
 * @brief Envoltura RAII para el estado dinámico de un hash criptográfico.
 */
class ScopedBCryptHash {
public:
    explicit ScopedBCryptHash(BCRYPT_ALG_HANDLE algHandle) {
        if (!algHandle) return;

        DWORD resultLength = 0;
        DWORD hashObjectSize = 0;
        NTSTATUS status = BCryptGetProperty(
            algHandle,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&hashObjectSize),
            sizeof(DWORD),
            &resultLength,
            0
        );

        if (!NT_SUCCESS(status) || hashObjectSize == 0) return;

        m_hashObject.resize(hashObjectSize);

        status = BCryptCreateHash(
            algHandle,
            &m_hashHandle,
            m_hashObject.data(),
            hashObjectSize,
            nullptr,
            0,
            0
        );

        if (!NT_SUCCESS(status)) {
            m_hashHandle = nullptr;
        }
    }

    ~ScopedBCryptHash() {
        if (m_hashHandle) {
            BCryptDestroyHash(m_hashHandle);
        }
    }

    bool update(const void* data, size_t length) {
        if (!m_hashHandle || !data || length == 0) return false;
        NTSTATUS status = BCryptHashData(
            m_hashHandle,
            reinterpret_cast<PUCHAR>(const_cast<void*>(data)),
            static_cast<ULONG>(length),
            0
        );
        return NT_SUCCESS(status);
    }

    std::string finalize(size_t expectedHashSize) {
        if (!m_hashHandle) return "";

        std::vector<UCHAR> hashBuffer(expectedHashSize);
        NTSTATUS status = BCryptFinishHash(
            m_hashHandle,
            hashBuffer.data(),
            static_cast<ULONG>(hashBuffer.size()),
            0
        );

        if (!NT_SUCCESS(status)) return "";

        std::ostringstream oss;
        for (UCHAR byte : hashBuffer) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }

    [[nodiscard]] bool isValid() const noexcept { return m_hashHandle != nullptr; }

    ScopedBCryptHash(const ScopedBCryptHash&) = delete;
    ScopedBCryptHash& operator=(const ScopedBCryptHash&) = delete;

private:
    BCRYPT_HASH_HANDLE m_hashHandle{nullptr};
    std::vector<UCHAR> m_hashObject;
};

} // namespace anónimo

FileHashes CryptoUtils::computeFileHashes(const std::filesystem::path& filePath, size_t chunkSize) {
    FileHashes result;

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec) || std::filesystem::is_directory(filePath, ec)) {
        return result;
    }

    ScopedBCryptAlg algSha256(BCRYPT_SHA256_ALGORITHM);
    ScopedBCryptAlg algSha1(BCRYPT_SHA1_ALGORITHM);
    ScopedBCryptAlg algMd5(BCRYPT_MD5_ALGORITHM);

    if (!algSha256.isValid() || !algSha1.isValid() || !algMd5.isValid()) {
        return result;
    }

    ScopedBCryptHash hashSha256(algSha256.get());
    ScopedBCryptHash hashSha1(algSha1.get());
    ScopedBCryptHash hashMd5(algMd5.get());

    if (!hashSha256.isValid() || !hashSha1.isValid() || !hashMd5.isValid()) {
        return result;
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return result;
    }

    std::vector<char> buffer(chunkSize);

    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        size_t bytesRead = static_cast<size_t>(file.gcount());
        if (bytesRead == 0) break;

        hashSha256.update(buffer.data(), bytesRead);
        hashSha1.update(buffer.data(), bytesRead);
        hashMd5.update(buffer.data(), bytesRead);
    }

    // Longitudes estándar de hash en bytes (SHA-256 = 32, SHA-1 = 20, MD5 = 16)
    result.sha256 = hashSha256.finalize(32);
    result.sha1   = hashSha1.finalize(20);
    result.md5    = hashMd5.finalize(16);

    result.success = (!result.sha256.empty() && !result.sha1.empty() && !result.md5.empty());
    return result;
}

std::string CryptoUtils::computeSha256(const std::filesystem::path& filePath) {
    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec) || std::filesystem::is_directory(filePath, ec)) {
        return "";
    }

    ScopedBCryptAlg alg(BCRYPT_SHA256_ALGORITHM);
    if (!alg.isValid()) return "";

    ScopedBCryptHash hash(alg.get());
    if (!hash.isValid()) return "";

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    std::vector<char> buffer(65536);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        size_t bytesRead = static_cast<size_t>(file.gcount());
        if (bytesRead == 0) break;
        hash.update(buffer.data(), bytesRead);
    }

    return hash.finalize(32);
}

std::string CryptoUtils::computeSha256FromBuffer(const void* data, size_t size) {
    if (!data || size == 0) return "";

    ScopedBCryptAlg alg(BCRYPT_SHA256_ALGORITHM);
    if (!alg.isValid()) return "";

    ScopedBCryptHash hash(alg.get());
    if (!hash.isValid()) return "";

    hash.update(data, size);
    return hash.finalize(32);
}

bool CryptoUtils::verifyIntegrity(const std::filesystem::path& filePath,
                                  const std::string& expectedSha256) {
    if (expectedSha256.empty()) return false;

    std::string actualHash = computeSha256(filePath);
    if (actualHash.empty()) return false;

    // Comparación case-insensitive constante para evitar ataques de temporización
    if (actualHash.length() != expectedSha256.length()) return false;

    int diff = 0;
    for (size_t i = 0; i < actualHash.length(); ++i) {
        diff |= (std::tolower(actualHash[i]) ^ std::tolower(expectedSha256[i]));
    }
    return (diff == 0);
}

} // namespace openguard
