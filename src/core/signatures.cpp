/**
 * @file signatures.cpp
 * @brief Implementación del motor de persistencia y consulta de firmas con SQLite3.
 * @details Implementa consultas parametrizadas para prevenir cualquier riesgo de inyección,
 *          uso de transacciones ACID para importaciones masivas y optimización mediante índices.
 */

#include "openguard/signatures.h"
#include "openguard/paths.h"

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>

namespace openguard {

namespace {

/**
 * @class ScopedStmt
 * @brief Envoltura RAII para liberar automáticamente sentencias preparadas de SQLite3.
 */
class ScopedStmt {
public:
    explicit ScopedStmt(sqlite3_stmt* stmt) : m_stmt(stmt) {}
    ~ScopedStmt() {
        if (m_stmt) {
            sqlite3_finalize(m_stmt);
            m_stmt = nullptr;
        }
    }
    ScopedStmt(const ScopedStmt&) = delete;
    ScopedStmt& operator=(const ScopedStmt&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return m_stmt; }

private:
    sqlite3_stmt* m_stmt{nullptr};
};

/**
 * @brief Convierte una cadena de caracteres a minúsculas estándar.
 * @param str Cadena original.
 * @return Cadena convertida a minúsculas.
 */
std::string toLower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return str;
}

/**
 * @brief Obtiene una cadena de texto de una columna de SQLite3 con valor por defecto seguro.
 * @param stmt Sentencia de SQLite.
 * @param col Índice de la columna.
 * @param fallback Valor alternativo en caso de ser nulo.
 * @return Cadena de texto correspondiente.
 */
inline std::string getColumnText(sqlite3_stmt* stmt, int col, const std::string& fallback = "") {
    const auto* txt = sqlite3_column_text(stmt, col);
    if (txt) {
        return reinterpret_cast<const char*>(txt);
    }
    return fallback;
}

/**
 * @brief Verifica que una cadena sea hexadecimal y tenga la longitud esperada.
 * @param s Cadena a validar (puede ser vacía si el hash es opcional).
 * @param expectedLen Longitud esperada en caracteres.
 * @return true si es vacía o es un hash hexadecimal válido de la longitud pedida.
 */
bool isValidHashOrEmpty(const std::string& s, size_t expectedLen) {
    if (s.empty()) return true;
    if (s.size() != expectedLen) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

} // namespace anónimo

SignatureDB::SignatureDB(const std::filesystem::path& dbPath) : m_dbPath(dbPath) {
    // Asegurar la existencia del directorio contenedor
    if (m_dbPath.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(m_dbPath.parent_path(), ec);
    }

    // SQLite exige rutas en UTF-8 (path::string() usaría la página de códigos ANSI y rompería rutas con acentos)
    const std::string pathUtf8 = paths::toUtf8(m_dbPath);

    // Apertura en modo multihilo seguro (SERIALIZED o NOMUTEX protegido por m_mutex)
    int rc = sqlite3_open_v2(
        pathUtf8.c_str(),
        &m_dbHandle,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc == SQLITE_OK && m_dbHandle) {
        sqlite3_busy_timeout(m_dbHandle, 5000); // El servicio y el CLI pueden acceder a la vez
        // SQLite degrada a solo lectura de forma silenciosa si el archivo está protegido contra escritura
        m_readOnly = (sqlite3_db_readonly(m_dbHandle, "main") == 1);
        if (!m_readOnly) initializeSchema();
        m_initialized = true;
        return;
    }

    if (m_dbHandle) {
        sqlite3_close(m_dbHandle);
        m_dbHandle = nullptr;
    }

    // Respaldo: un usuario sin permisos de escritura aún puede consultar una base existente
    rc = sqlite3_open_v2(pathUtf8.c_str(), &m_dbHandle,
                         SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc == SQLITE_OK && m_dbHandle) {
        sqlite3_busy_timeout(m_dbHandle, 5000);
        m_readOnly = true;
        m_initialized = true;
    } else if (m_dbHandle) {
        sqlite3_close(m_dbHandle);
        m_dbHandle = nullptr;
    }
}

SignatureDB::~SignatureDB() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dbHandle) {
        sqlite3_close_v2(m_dbHandle);
        m_dbHandle = nullptr;
    }
}

bool SignatureDB::isOpen() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_dbHandle != nullptr && m_initialized;
}

void SignatureDB::initializeSchema() {
    const char* schemaSql =
        "CREATE TABLE IF NOT EXISTS signatures ("
        "    id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "    sha256       TEXT UNIQUE,"
        "    sha1         TEXT,"
        "    md5          TEXT,"
        "    malware_name TEXT NOT NULL,"
        "    threat_type  TEXT NOT NULL DEFAULT 'malware',"
        "    severity     TEXT NOT NULL DEFAULT 'high',"
        "    source       TEXT DEFAULT 'openguard',"
        "    added_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sig_sha256 ON signatures(sha256);"
        "CREATE INDEX IF NOT EXISTS idx_sig_sha1   ON signatures(sha1);"
        "CREATE INDEX IF NOT EXISTS idx_sig_md5    ON signatures(md5);"
        // Índices únicos: evitan duplicados al reimportar listas que solo traen SHA-1 o MD5 (los NULL no colisionan)
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_sig_sha1 ON signatures(sha1);"
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_sig_md5  ON signatures(md5);"
        "PRAGMA journal_mode = WAL;"
        "PRAGMA synchronous = NORMAL;";

    char* err = nullptr;
    sqlite3_exec(m_dbHandle, schemaSql, nullptr, nullptr, &err);
    if (err) {
        sqlite3_free(err);
    }
}

std::optional<SignatureRecord> SignatureDB::lookup(const std::string& sha256,
                                                   const std::string& sha1,
                                                   const std::string& md5) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return std::nullopt;

    auto queryByField = [this](const char* field, const std::string& hashVal) -> std::optional<SignatureRecord> {
        if (hashVal.empty()) return std::nullopt;

        std::string sql = "SELECT id, sha256, sha1, md5, malware_name, threat_type, severity, source "
                          "FROM signatures WHERE " + std::string(field) + " = ? LIMIT 1;";

        sqlite3_stmt* rawStmt = nullptr;
        int rc = sqlite3_prepare_v2(m_dbHandle, sql.c_str(), -1, &rawStmt, nullptr);
        if (rc != SQLITE_OK) return std::nullopt;

        ScopedStmt stmt(rawStmt);
        std::string normHash = toLower(hashVal);
        sqlite3_bind_text(stmt.get(), 1, normHash.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            SignatureRecord rec;
            rec.id          = sqlite3_column_int(stmt.get(), 0);
            rec.sha256      = getColumnText(stmt.get(), 1);
            rec.sha1        = getColumnText(stmt.get(), 2);
            rec.md5         = getColumnText(stmt.get(), 3);
            rec.malwareName = getColumnText(stmt.get(), 4, "Desconocido");
            rec.threatType  = getColumnText(stmt.get(), 5, "unknown");
            rec.severity    = getColumnText(stmt.get(), 6, "high");
            rec.source      = getColumnText(stmt.get(), 7, "openguard");
            return rec;
        }

        return std::nullopt;
    };

    // 1. Búsqueda prioritaria por SHA-256
    if (!sha256.empty()) {
        auto match = queryByField("sha256", sha256);
        if (match.has_value()) return match;
    }

    // 2. Búsqueda secundaria por SHA-1
    if (!sha1.empty()) {
        auto match = queryByField("sha1", sha1);
        if (match.has_value()) return match;
    }

    // 3. Búsqueda por MD5
    if (!md5.empty()) {
        auto match = queryByField("md5", md5);
        if (match.has_value()) return match;
    }

    return std::nullopt;
}

bool SignatureDB::addSignature(const SignatureRecord& record) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return false;

    const char* sql =
        "INSERT OR REPLACE INTO signatures (sha256, sha1, md5, malware_name, threat_type, severity, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* rawStmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, sql, -1, &rawStmt, nullptr) != SQLITE_OK) {
        return false;
    }
    ScopedStmt stmt(rawStmt);

    std::string s256 = toLower(record.sha256);
    std::string s1   = toLower(record.sha1);
    std::string smd5 = toLower(record.md5);

    sqlite3_bind_text(stmt.get(), 1, s256.empty() ? nullptr : s256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, s1.empty() ? nullptr : s1.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, smd5.empty() ? nullptr : smd5.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, record.malwareName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, record.threatType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, record.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, record.source.c_str(), -1, SQLITE_TRANSIENT);

    return (sqlite3_step(stmt.get()) == SQLITE_DONE);
}

bool SignatureDB::bulkImport(const std::vector<SignatureRecord>& records, size_t& inserted, size_t& skipped) {
    inserted = 0;
    skipped = 0;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle || m_readOnly || records.empty()) return false;

    // Uso de transacción atómica para rendimiento masivo
    sqlite3_exec(m_dbHandle, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* sql =
        "INSERT OR IGNORE INTO signatures (sha256, sha1, md5, malware_name, threat_type, severity, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* rawStmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, sql, -1, &rawStmt, nullptr) != SQLITE_OK) {
        sqlite3_exec(m_dbHandle, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }
    ScopedStmt stmt(rawStmt);

    for (const auto& rec : records) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());

        std::string s256 = toLower(rec.sha256);
        std::string s1   = toLower(rec.sha1);
        std::string smd5 = toLower(rec.md5);

        sqlite3_bind_text(stmt.get(), 1, s256.empty() ? nullptr : s256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, s1.empty() ? nullptr : s1.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 3, smd5.empty() ? nullptr : smd5.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, rec.malwareName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 5, rec.threatType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 6, rec.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 7, rec.source.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt.get()) == SQLITE_DONE) { if (sqlite3_changes(m_dbHandle) > 0) { inserted++; } else { skipped++; } } else { skipped++; }
    }

    sqlite3_exec(m_dbHandle, "COMMIT;", nullptr, nullptr, nullptr);
    return true;
}

void SignatureDB::seedEicar() {
    // Archivo de prueba estándar EICAR (68 bytes) y sus variantes habituales con salto de línea final.
    struct EicarVariant { const char* name; const char* sha256; const char* sha1; const char* md5; };
    static const EicarVariant kVariants[] = {
        {"EICAR-Standard-AV-Test-File",
         "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
         "3395856ce81f2b7382dee72602f798b642f14140",
         "44d88612fea8a8f36de82e1278abb02f"},
        {"EICAR-Standard-AV-Test-File-LF",
         "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
         "cf8bd9dfddff007f75adf4c2be48005cea317c62",
         "69630e4574ec6798239b091cda43dca0"},
        {"EICAR-Standard-AV-Test-File-CRLF",
         "8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71",
         "a6c80ce949469cc86f6c22355f4d3bb8773fc634",
         "e7e5fa40569514ec442bbdf755d89c2f"},
    };

    for (const auto& v : kVariants) {
        SignatureRecord rec;
        rec.sha256 = v.sha256;
        rec.sha1 = v.sha1;
        rec.md5 = v.md5;
        rec.malwareName = v.name;
        rec.threatType = "test_file";
        rec.severity = "high";
        rec.source = "eicar";
        addSignature(rec);
    }
}

bool SignatureDB::importFromJson(const std::filesystem::path& jsonPath, size_t& inserted, size_t& skipped) {
    inserted = 0;
    skipped = 0;

    std::ifstream in(jsonPath, std::ios::binary);
    if (!in.is_open()) return false;

    nlohmann::json doc = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.is_object()) return false;

    auto sigsIt = doc.find("signatures");
    if (sigsIt == doc.end() || !sigsIt->is_array()) return false;

    std::vector<SignatureRecord> records;
    records.reserve(sigsIt->size());

    for (const auto& entry : *sigsIt) {
        if (!entry.is_object()) { ++skipped; continue; }

        auto str = [&entry](const char* key, const char* fallback) -> std::string {
            auto it = entry.find(key);
            return (it != entry.end() && it->is_string()) ? it->get<std::string>() : std::string(fallback);
        };

        SignatureRecord rec;
        rec.sha256 = toLower(str("sha256", ""));
        rec.sha1 = toLower(str("sha1", ""));
        rec.md5 = toLower(str("md5", ""));
        rec.malwareName = str("malware_name", "");
        rec.threatType = str("threat_type", "malware");
        rec.severity = str("severity", "high");
        rec.source = str("source", "openguard");

        const bool anyHash = !rec.sha256.empty() || !rec.sha1.empty() || !rec.md5.empty();
        if (!anyHash || rec.malwareName.empty() ||
            !isValidHashOrEmpty(rec.sha256, 64) ||
            !isValidHashOrEmpty(rec.sha1, 40) ||
            !isValidHashOrEmpty(rec.md5, 32)) {
            ++skipped; // Registro malformado: se descarta sin abortar la importación
            continue;
        }
        records.push_back(std::move(rec));
    }

    if (records.empty()) return true;

    size_t ins = 0, skp = 0;
    const bool ok = bulkImport(records, ins, skp);
    inserted = ins;
    skipped += skp;
    return ok;
}

SignatureStats SignatureDB::getStats() {
    SignatureStats stats;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return stats;

    // Total de firmas
    sqlite3_stmt* rawStmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, "SELECT COUNT(*) FROM signatures;", -1, &rawStmt, nullptr) == SQLITE_OK) {
        ScopedStmt stmt(rawStmt);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            stats.totalSignatures = static_cast<size_t>(sqlite3_column_int64(stmt.get(), 0));
        }
    }

    // Agrupación por severidad
    if (sqlite3_prepare_v2(m_dbHandle, "SELECT severity, COUNT(*) FROM signatures GROUP BY severity;", -1, &rawStmt, nullptr) == SQLITE_OK) {
        ScopedStmt stmt(rawStmt);
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            std::string sev = getColumnText(stmt.get(), 0);
            size_t cnt = static_cast<size_t>(sqlite3_column_int64(stmt.get(), 1));
            stats.bySeverity.emplace_back(sev, cnt);
        }
    }

    // Agrupación por tipo de amenaza
    if (sqlite3_prepare_v2(m_dbHandle, "SELECT threat_type, COUNT(*) FROM signatures GROUP BY threat_type;", -1, &rawStmt, nullptr) == SQLITE_OK) {
        ScopedStmt stmt(rawStmt);
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            std::string type = getColumnText(stmt.get(), 0);
            size_t cnt = static_cast<size_t>(sqlite3_column_int64(stmt.get(), 1));
            stats.byType.emplace_back(type, cnt);
        }
    }

    return stats;
}

} // namespace openguard

namespace openguard {

bool SignatureDB::importHashList(const std::string& text, const std::string& malwareName,
                                 const std::string& source, size_t& inserted, size_t& skipped) {
    inserted = 0;
    skipped = 0;

    std::vector<SignatureRecord> records;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = text.substr(pos, eol - pos);
        pos = eol + 1;

        // Quitar espacios/CR y todo lo posterior a un separador (admite "hash,campo2" y "hash comentario")
        size_t b = line.find_first_not_of(" \t\r");
        if (b == std::string::npos || line[b] == '#') continue;
        size_t e = line.find_first_of(" \t\r,;", b);
        std::string token = toLower(line.substr(b, e == std::string::npos ? std::string::npos : e - b));
        if (!token.empty() && token.front() == '"') token.erase(0, 1);
        if (!token.empty() && token.back() == '"') token.pop_back();

        SignatureRecord rec;
        if (token.size() == 64 && isValidHashOrEmpty(token, 64)) rec.sha256 = token;
        else if (token.size() == 40 && isValidHashOrEmpty(token, 40)) rec.sha1 = token;
        else if (token.size() == 32 && isValidHashOrEmpty(token, 32)) rec.md5 = token;
        else { ++skipped; continue; }

        rec.malwareName = malwareName;
        rec.threatType = "malware";
        rec.severity = "high";
        rec.source = source;
        records.push_back(std::move(rec));
    }

    if (records.empty()) return true;
    size_t ins = 0, skp = 0;
    const bool ok = bulkImport(records, ins, skp);
    inserted = ins;
    skipped += skp;
    return ok;
}

} // namespace openguard
