/**
 * @file feeds.h
 * @brief Fuentes de firmas y reglas: importadores (MalwareBazaar, ClamAV) y actualización verificada.
 * @details - Oficial (repositorio de OpenGuard): índice de firmas y reglas YARA con FIRMA ECDSA verificada; si la
 *            firma no es válida, nada se importa.
 *          - MalwareBazaar (abuse.ch): hashes recientes en CSV; requiere clave de autenticación de abuse.ch, que se
 *            guarda cifrada con DPAPI en el SecretStore (nombre "abusech_auth_key"). Solo HTTPS.
 *          - ClamAV: se importan bases de hashes en texto (.hdb/.hsb/.mdb). Las bases comprimidas (.cvd/.cld) no.
 */

#pragma once

#include "openguard/secrets.h"
#include "openguard/signatures.h"

#include <filesystem>
#include <string>
#include <vector>

namespace openguard {

struct FeedStats {
    size_t parsed{0};   ///< Registros válidos extraídos.
    size_t skipped{0};  ///< Líneas ignoradas (comentarios excluidos): inválidas.
};

/// Interpreta el CSV de "recent additions" de MalwareBazaar (comentarios con '#', campos entre comillas).
FeedStats parseMalwareBazaarCsv(const std::string& text, std::vector<SignatureRecord>& out);

/// Interpreta una base de hashes de ClamAV en texto: líneas "hash:tamaño:nombre" (MD5, SHA-1 o SHA-256).
FeedStats parseClamAvHashDb(const std::string& text, std::vector<SignatureRecord>& out);

struct FeedOptions {
    bool official{true};     ///< Índice de firmas oficial (firma verificada).
    bool rules{true};        ///< Reglas YARA oficiales (manifiesto firmado).
    bool bazaar{false};      ///< MalwareBazaar (requiere clave en el SecretStore).
    std::string officialBaseUrl{"https://raw.githubusercontent.com/WilliamsAlexis/OpenGuard/main/signatures"};
    std::string bazaarUrl{"https://bazaar.abuse.ch/export/csv/recent/"};
    std::filesystem::path rulesDir;   ///< Destino de las reglas descargadas (vacío = %ProgramData%\OpenGuard\rules).
};

struct FeedResult {
    std::string feed;                 ///< "official" | "rules" | "bazaar"
    bool ok{false};
    bool signatureVerified{false};
    size_t inserted{0};               ///< Firmas nuevas o reglas escritas.
    size_t skipped{0};
    std::string error;
};

/// Nombre con el que se guarda la clave de abuse.ch en el SecretStore.
inline constexpr const char* kAbuseChSecret = "abusech_auth_key";

/**
 * @brief Descarga e importa las fuentes habilitadas. Cada fuente es independiente: el fallo de una no afecta a las demás.
 */
std::vector<FeedResult> updateFeeds(SignatureDB& db, const FeedOptions& options, const SecretStore& secrets);

} // namespace openguard
