/**
 * @file history.cpp
 * @brief Implementación del historial de amenazas en SQLite.
 */

#include "openguard/history.h"
#include "openguard/paths.h"

#include <sqlite3.h>

#include <chrono>
#include <ctime>

namespace openguard {

namespace {

std::string nowLocal() {
    const std::time_t tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm lt{};
    localtime_s(&lt, &tt);
    char buf[24]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &lt);
    return buf;
}

std::string col(sqlite3_stmt* st, int i) {
    const unsigned char* t = sqlite3_column_text(st, i);
    return t ? reinterpret_cast<const char*>(t) : std::string();
}

} // namespace

ThreatHistory::ThreatHistory(const std::filesystem::path& dbPath) {
    std::error_code ec;
    if (dbPath.has_parent_path()) std::filesystem::create_directories(dbPath.parent_path(), ec);

    const std::string utf8 = paths::toUtf8(dbPath);
    int rc = sqlite3_open_v2(utf8.c_str(), &m_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        if (m_db) sqlite3_close(m_db);
        m_db = nullptr;
        // Respaldo de solo lectura para consultar el historial sin privilegios
        rc = sqlite3_open_v2(utf8.c_str(), &m_db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nullptr);
        if (rc != SQLITE_OK) {
            if (m_db) sqlite3_close(m_db);
            m_db = nullptr;
        }
        return;
    }

    sqlite3_busy_timeout(m_db, 5000);
    if (sqlite3_db_readonly(m_db, "main") == 1) return;
    sqlite3_exec(m_db,
        "CREATE TABLE IF NOT EXISTS events ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ts TEXT NOT NULL, level TEXT NOT NULL, kind TEXT NOT NULL,"
        " path TEXT, threat TEXT, action TEXT, sha256 TEXT, details TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);"
        "CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);",
        nullptr, nullptr, nullptr);
}

ThreatHistory::~ThreatHistory() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) sqlite3_close_v2(m_db);
}

bool ThreatHistory::record(const HistoryEvent& e) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return false;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(m_db,
            "INSERT INTO events (ts, level, kind, path, threat, action, sha256, details) VALUES (?,?,?,?,?,?,?,?);",
            -1, &st, nullptr) != SQLITE_OK) return false;

    const std::string ts = e.timestamp.empty() ? nowLocal() : e.timestamp;
    const std::string* vals[] = {&ts, &e.level, &e.kind, &e.path, &e.threat, &e.action, &e.sha256, &e.details};
    for (int i = 0; i < 8; ++i) sqlite3_bind_text(st, i + 1, vals[i]->c_str(), -1, SQLITE_TRANSIENT);

    const bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

std::vector<HistoryEvent> ThreatHistory::recent(size_t limit, const std::string& kindFilter) {
    std::vector<HistoryEvent> out;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return out;

    const std::string sql = std::string("SELECT id, ts, level, kind, path, threat, action, sha256, details FROM events") +
                            (kindFilter.empty() ? "" : " WHERE kind = ?") + " ORDER BY id DESC LIMIT ?;";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return out;

    int idx = 1;
    if (!kindFilter.empty()) sqlite3_bind_text(st, idx++, kindFilter.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, idx, static_cast<sqlite3_int64>(limit));

    while (sqlite3_step(st) == SQLITE_ROW) {
        HistoryEvent e;
        e.id = sqlite3_column_int64(st, 0);
        e.timestamp = col(st, 1);
        e.level = col(st, 2);
        e.kind = col(st, 3);
        e.path = col(st, 4);
        e.threat = col(st, 5);
        e.action = col(st, 6);
        e.sha256 = col(st, 7);
        e.details = col(st, 8);
        out.push_back(std::move(e));
    }
    sqlite3_finalize(st);
    return out;
}

size_t ThreatHistory::count(const std::string& kindFilter) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) return 0;

    const std::string sql = std::string("SELECT COUNT(*) FROM events") + (kindFilter.empty() ? "" : " WHERE kind = ?") + ";";
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return 0;
    if (!kindFilter.empty()) sqlite3_bind_text(st, 1, kindFilter.c_str(), -1, SQLITE_TRANSIENT);

    size_t n = 0;
    if (sqlite3_step(st) == SQLITE_ROW) n = static_cast<size_t>(sqlite3_column_int64(st, 0));
    sqlite3_finalize(st);
    return n;
}

size_t ThreatHistory::purgeOlderThan(int days) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db || days <= 0) return 0;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(m_db, "DELETE FROM events WHERE ts < datetime('now', 'localtime', ?);", -1, &st, nullptr) != SQLITE_OK) return 0;
    const std::string modifier = "-" + std::to_string(days) + " days";
    sqlite3_bind_text(st, 1, modifier.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
    return static_cast<size_t>(sqlite3_changes(m_db));
}

} // namespace openguard
