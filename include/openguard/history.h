/**
 * @file history.h
 * @brief Historial estructurado de amenazas y eventos de protección (SQLite).
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3;

namespace openguard {

struct HistoryEvent {
    long long id{0};
    std::string timestamp;   ///< "YYYY-MM-DD HH:MM:SS" (hora local).
    std::string level;       ///< INFO | WARN | ALERT | ACTION | ERROR.
    std::string kind;        ///< detection | quarantine | ransomware | update | system ...
    std::string path;        ///< Ruta del archivo (UTF-8) si aplica.
    std::string threat;      ///< Nombre de la amenaza o descripción corta.
    std::string action;      ///< Acción tomada (aislado, solo registrado, ...).
    std::string sha256;
    std::string details;
};

/**
 * @class ThreatHistory
 * @brief Registro persistente consultable de detecciones y acciones. Seguro entre hilos y procesos.
 */
class ThreatHistory {
public:
    explicit ThreatHistory(const std::filesystem::path& dbPath);
    ~ThreatHistory();
    ThreatHistory(const ThreatHistory&) = delete;
    ThreatHistory& operator=(const ThreatHistory&) = delete;

    [[nodiscard]] bool isOpen() const noexcept { return m_db != nullptr; }

    /// Registra un evento. @return false si la base no está disponible (p. ej. solo lectura).
    bool record(const HistoryEvent& e);

    /// Eventos más recientes primero.
    [[nodiscard]] std::vector<HistoryEvent> recent(size_t limit = 200, const std::string& kindFilter = {});

    [[nodiscard]] size_t count(const std::string& kindFilter = {});

    /// Elimina eventos anteriores a N días (mantenimiento). @return filas borradas.
    size_t purgeOlderThan(int days);

private:
    sqlite3* m_db{nullptr};
    std::mutex m_mutex;
};

} // namespace openguard
