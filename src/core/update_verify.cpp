/**
 * @file update_verify.cpp
 * @brief Implementación de la verificación de firmas de actualización.
 */

#include "openguard/update_verify.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

namespace openguard {

const EcPublicKey& officialUpdateKey() {
    static const EcPublicKey key = {
        {0xAC, 0x80, 0x64, 0x8E, 0x5E, 0x4C, 0xD4, 0x64, 0xA1, 0xE5, 0xFF, 0x73, 0x33, 0x72, 0xCC, 0x1E,
         0x4F, 0xC5, 0x3B, 0x58, 0xC6, 0x3A, 0x76, 0x89, 0x48, 0x79, 0xF2, 0x90, 0x75, 0x8D, 0x7C, 0x9B},
        {0x9A, 0x2C, 0x93, 0xCE, 0xC8, 0x50, 0x19, 0xB7, 0xF9, 0xD1, 0xD1, 0x43, 0x51, 0xD3, 0x96, 0x1C,
         0x4C, 0xE3, 0xDB, 0xE5, 0xCC, 0x36, 0x03, 0x87, 0xFD, 0x8E, 0x62, 0xB8, 0x6F, 0x47, 0x81, 0xE5}};
    return key;
}

namespace {

/// SHA-256 en bytes crudos (BCrypt).
bool sha256Raw(const void* data, size_t size, std::array<uint8_t, 32>& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) return false;

    bool ok = false;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (NT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
        const auto* bytes = static_cast<const uint8_t*>(data);
        size_t offset = 0;
        bool good = true;
        while (offset < size && good) {
            const size_t chunk = size - offset > (1u << 24) ? (1u << 24) : size - offset;
            good = NT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(bytes + offset), static_cast<ULONG>(chunk), 0));
            offset += chunk;
        }
        ok = good && NT_SUCCESS(BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0));
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

} // namespace

bool verifyEcdsaP256(const void* data, size_t size, const std::vector<uint8_t>& signature, const EcPublicKey& key) {
    if (signature.size() != 64) return false;

    std::array<uint8_t, 32> digest{};
    if (!sha256Raw(data, size, digest)) return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) return false;

    // Blob de clave pública: cabecera (magic + longitud) seguida de X e Y
    std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), key.x.data(), 32);
    std::memcpy(blob.data() + sizeof(header) + 32, key.y.data(), 32);

    bool valid = false;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (NT_SUCCESS(BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &hKey, blob.data(), static_cast<ULONG>(blob.size()), 0))) {
        valid = NT_SUCCESS(BCryptVerifySignature(hKey, nullptr, digest.data(), static_cast<ULONG>(digest.size()),
                                                 const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0));
        BCryptDestroyKey(hKey);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return valid;
}

bool verifyOfficialSignature(const std::string& data, const std::string& signatureBase64) {
    const auto sig = base64Decode(signatureBase64);
    if (sig.empty()) return false;
    return verifyEcdsaP256(data.data(), data.size(), sig, officialUpdateKey());
}

std::vector<uint8_t> base64Decode(const std::string& text) {
    static const std::string kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> out;
    uint32_t buffer = 0;
    int bits = 0;
    size_t padding = 0;

    for (char c : text) {
        if (c == '=') { ++padding; continue; }
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (padding > 0) return {}; // caracteres tras el relleno: formato inválido
        const size_t v = kAlphabet.find(c);
        if (v == std::string::npos) return {};
        buffer = (buffer << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

std::string base64Encode(const std::vector<uint8_t>& bytes) {
    static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 2 < bytes.size()) {
        const uint32_t n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
        out.push_back(kAlphabet[(n >> 6) & 63]);
        out.push_back(kAlphabet[n & 63]);
        i += 3;
    }
    if (i + 1 == bytes.size()) {
        const uint32_t n = bytes[i] << 16;
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
        out += "==";
    } else if (i + 2 == bytes.size()) {
        const uint32_t n = (bytes[i] << 16) | (bytes[i + 1] << 8);
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
        out.push_back(kAlphabet[(n >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

} // namespace openguard
