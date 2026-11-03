/**
 * @file signatures.cpp
 * @brief Implementación del motor de persistencia y consulta de firmas con SQLite3.
 * @details Implementa consultas parametrizadas para prevenir cualquier riesgo de inyección,
 *          uso de transacciones ACID para importaciones masivas y optimización mediante índices.
 */

#include "openguard/signatures.h"

#include <sqlite3.h>
#include <iostream>
#include <algorithm>

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

} // namespace anónimo

SignatureDB::SignatureDB(const std::filesystem::path& dbPath) : m_dbPath(dbPath) {
    // Asegurar la existencia del directorio contenedor
    if (m_dbPath.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(m_dbPath.parent_path(), ec);
    }

    // Apertura en modo multihilo seguro (SERIALIZED o NOMUTEX protegido por m_mutex)
    std::string pathUtf8 = m_dbPath.string();
    int rc = sqlite3_open_v2(
        pathUtf8.c_str(),
        &m_dbHandle,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc == SQLITE_OK && m_dbHandle) {
        initializeSchema();
        m_initialized = true;
    } else {
        if (m_dbHandle) {
            sqlite3_close(m_dbHandle);
            m_dbHandle = nullptr;
        }
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
        "    threat_type  TEXT DEFAULT 'unknown',"
        "    severity     TEXT DEFAULT 'high',"
        "    added_date   TEXT DEFAULT (datetime('now')),"
        "    source       TEXT DEFAULT 'openguard'"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sig_sha256 ON signatures(sha256);"
        "CREATE INDEX IF NOT EXISTS idx_sig_sha1   ON signatures(sha1);"
        "CREATE INDEX IF NOT EXISTS idx_sig_md5    ON signatures(md5);";

    char* errMsg = nullptr;
    sqlite3_exec(m_dbHandle, schemaSql, nullptr, nullptr, &errMsg);
    if (errMsg) {
        sqlite3_free(errMsg);
    }
}

std::optional<SignatureRecord> SignatureDB::lookup(
    const std::string& sha256,
    const std::string& sha1,
    const std::string& md5
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return std::nullopt;

    // Función auxiliar interna para ejecutar la búsqueda parametrizada
    auto queryByField = [this](const char* fieldName, const std::string& hashVal)
        -> std::optional<SignatureRecord> {
        if (hashVal.empty()) return std::nullopt;

        std::string sql = "SELECT id, sha256, sha1, md5, malware_name, threat_type, severity, source "
                          "FROM signatures WHERE ";
        sql += fieldName;
        sql += " = ? LIMIT 1;";

        sqlite3_stmt* rawStmt = nullptr;
        int rc = sqlite3_prepare_v2(m_dbHandle, sql.c_str(), -1, &rawStmt, nullptr);
        if (rc != SQLITE_OK) return std::nullopt;

        ScopedStmt stmt(rawStmt);
        std::string normHash = toLower(hashVal);
        sqlite3_bind_text(stmt.get(), 1, normHash.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            SignatureRecord rec;
            rec.id = sqlite3_column_int(stmt.get(), 0);
            rec.sha256 = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1) ?: reinterpret_cast<const unsigned char*>(""));
            rec.sha1   = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2) ?: reinterpret_cast<const unsigned char*>(""));
            rec.md5    = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3) ?: reinterpret_cast<const unsigned char*>(""));
            rec.malwareName = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4) ?: reinterpret_cast<const unsigned char*>("Desconocido"));
            rec.threatType  = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5) ?: reinterpret_cast<const unsigned char*>("unknown"));
            rec.severity    = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 6) ?: reinterpret_cast<const unsigned char*>("high"));
            rec.source      = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 7) ?: reinterpret_cast<const unsigned char*>("openguard"));
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
        "INSERT OR IGNORE INTO signatures (sha256, sha1, md5, malware_name, threat_type, severity, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* rawStmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, sql, -1, &rawStmt, nullptr) != SQLITE_OK) {
        return false;
    }
    ScopedStmt stmt(rawStmt);

    std::string s256 = toLower(record.sha256);
    std::string s1   = toLower(record.sha1);
    std::string smd5 = toLower(record.md5);

    sqlite3_bind_text(stmt.get(), 1, s256.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, s1.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, smd5.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, record.malwareName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, record.threatType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, record.severity.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, record.source.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt.get());
    return (rc == SQLITE_DONE) && (sqlite3_changes(m_dbHandle) > 0);
}

bool SignatureDB::bulkImport(const std::vector<SignatureRecord>& records,
                             size_t& inserted,
                             size_t& skipped) {
    inserted = 0;
    skipped = 0;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return false;

    // Iniciar transacción atómica ACID para alto rendimiento
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

        sqlite3_bind_text(stmt.get(), 1, s256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 2, s1.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 3, smd5.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 4, rec.malwareName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 5, rec.threatType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 6, rec.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt.get(), 7, rec.source.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt.get()) == SQLITE_DONE) {
            if (sqlite3_changes(m_dbHandle) > 0) {
                inserted++;
            } else {
                skipped++;
            }
        } else {
            skipped++;
        }
    }

    sqlite3_exec(m_dbHandle, "COMMIT;", nullptr, nullptr, nullptr);
    return true;
}

void SignatureDB::seedEicar() {
    // 1. Firma estándar histórica de EICAR
    SignatureRecord eicar1;
    eicar1.sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    eicar1.sha1   = "3395856ce81f2b7382dee72602f798b642f14d8";
    eicar1.md5    = "44d88612fea8a8f36de82e1278abb02f";
    eicar1.malwareName = "EICAR-Standard-AV-Test-File";
    eicar1.threatType  = "test_file";
    eicar1.severity    = "low";
    eicar1.source      = "eicar";
    addSignature(eicar1);

    // 2. Hash directo de la cadena de 68 bytes EICAR
    SignatureRecord eicar2;
    eicar2.sha256 = "13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa";
    eicar2.sha1   = "02dc45ac70bbaec8a8cfff5b119fa52ca6e991f4";
    eicar2.md5    = "c637d527c86186464879dc45e7816c53";
    eicar2.malwareName = "EICAR-Standard-AV-Test-File-Raw";
    eicar2.threatType  = "test_file";
    eicar2.severity    = "low";
    eicar2.source      = "eicar";
    addSignature(eicar2);
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
            std::string sev = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0) ?: reinterpret_cast<const unsigned char*>(""));
            size_t cnt = static_cast<size_t>(sqlite3_column_int64(stmt.get(), 1));
            stats.bySeverity.emplace_back(sev, cnt);
        }
    }

    // Agrupación por tipo de amenaza
    if (sqlite3_prepare_v2(m_dbHandle, "SELECT threat_type, COUNT(*) FROM signatures GROUP BY threat_type;", -1, &rawStmt, nullptr) == SQLITE_OK) {
        ScopedStmt stmt(rawStmt);
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            std::string type = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0) ?: reinterpret_cast<const unsigned char*>(""));
            size_t cnt = static_cast<size_t>(sqlite3_column_int64(stmt.get(), 1));
            stats.byType.emplace_back(type, cnt);
        }
    }

    return stats;
}

} // namespace openguard

