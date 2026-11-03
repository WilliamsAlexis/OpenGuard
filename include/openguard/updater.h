/**
 * @file updater.h
 * @brief Actualización de la base de firmas desde una URL HTTPS (compartida por CLI y GUI).
 */

#pragma once

#include "openguard/signatures.h"

#include <cstddef>
#include <string>

namespace openguard {

/// URL por defecto del índice de firmas del repositorio oficial.
inline constexpr const char* kDefaultSignatureUrl =
    "https://raw.githubusercontent.com/WilliamsAlexis/OpenGuard/main/signatures/hashes_index.json";

struct UpdateResult {
    bool ok{false};
    size_t inserted{0};
    size_t skipped{0};
    std::string error;
};

/**
 * @brief Descarga e importa firmas. Acepta un JSON de OpenGuard o una lista de hashes (uno por línea).
 * @param db Base de firmas (debe ser escribible).
 * @param url URL https:// a descargar.
 * @param authKey Clave opcional para el encabezado Auth-Key.
 * @param listName Nombre de detección para listas de hashes en texto plano.
 */
UpdateResult updateSignaturesOnline(SignatureDB& db, const std::string& url = kDefaultSignatureUrl,
                                    const std::string& authKey = {}, const std::string& listName = "Imported.HashList");

} // namespace openguard
