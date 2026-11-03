/**
 * @file update_verify.h
 * @brief Verificación criptográfica de actualizaciones (ECDSA P-256 + SHA-256, Windows CNG) y utilidades de base64.
 * @details Las firmas y reglas del repositorio oficial se firman fuera de línea con una clave privada que nunca
 *          sale del equipo del mantenedor; el programa solo incorpora la clave pública. Así, aunque alguien
 *          comprometa el alojamiento o intercepte la descarga, no puede inyectar firmas ni reglas falsas
 *          (por ejemplo, para que OpenGuard ignore malware o marque archivos legítimos como amenazas).
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace openguard {

/// Clave pública ECDSA P-256 (coordenadas X e Y de 32 bytes).
struct EcPublicKey {
    std::array<uint8_t, 32> x{};
    std::array<uint8_t, 32> y{};
};

/// Clave pública de actualizaciones incorporada en el programa (par generado por el mantenedor).
[[nodiscard]] const EcPublicKey& officialUpdateKey();

/**
 * @brief Verifica una firma ECDSA P-256 sobre SHA-256(data).
 * @param signature Firma en formato IEEE P1363 (r || s, 64 bytes), el que produce .NET ECDsa.SignData.
 */
[[nodiscard]] bool verifyEcdsaP256(const void* data, size_t size, const std::vector<uint8_t>& signature, const EcPublicKey& key);

/// Verifica con la clave oficial. `signatureBase64` es el contenido del archivo .sig (se ignoran espacios y saltos).
[[nodiscard]] bool verifyOfficialSignature(const std::string& data, const std::string& signatureBase64);

/// Decodifica base64 estándar (tolera saltos de línea y espacios). Devuelve vacío si es inválido.
[[nodiscard]] std::vector<uint8_t> base64Decode(const std::string& text);

/// Codifica en base64 estándar.
[[nodiscard]] std::string base64Encode(const std::vector<uint8_t>& bytes);

} // namespace openguard
