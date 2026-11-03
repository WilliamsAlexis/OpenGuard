/**
 * @file scanner.cpp
 * @brief Implementación del motor de escaneo multihilo y cotejo de firmas.
 * @details Este módulo ejecuta la inspección concurrente de archivos sobre el sistema de archivos
 *          de Windows con soporte de exclusión de enlaces simbólicos conflictivos y tolerancia a fallos.
 */

#include "openguard/scanner.h"
#include "openguard/crypto_utils.h"
#include "openguard/paths.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <future>
#include <mutex>
#include <unordered_set>

namespace openguard {

namespace {

/**
 * @brief Convierte una cadena a minúsculas estándar.
 * @param str Cadena de entrada.
 * @return Cadena en minúsculas.
 */
std::string toLowerStr(std::string str) {
    for (char& c : str) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return str;
}

} // namespace anónimo

FileScanner::FileScanner(std::shared_ptr<SignatureDB> sigDb, ScannerConfig config)
    : m_sigDb(std::move(sigDb)), m_config(config) {
    m_threadPool = std::make_unique<ThreadPool>(m_config.threadCount, m_config.lowPriority);
    m_heuristics = std::make_unique<HeuristicsEngine>();
    if (!m_config.yaraRulesDir.empty()) {
        m_yara = std::make_unique<YaraLite>();
        m_yara->loadDirectory(m_config.yaraRulesDir);
    }
}

ScanResult FileScanner::scanFile(const std::filesystem::path& filePath) {
    ScanResult result;
    result.filePath = filePath;

    auto tStart = std::chrono::high_resolution_clock::now();

    // 1. Verificación preliminar de existencia y tamaño
    std::error_code ec;
    auto fileStatus = std::filesystem::status(filePath, ec);
    if (ec || !std::filesystem::exists(fileStatus)) {
        result.skipped = true;
        result.error = "Archivo no encontrado o inaccesible";
        return result;
    }

    if (!std::filesystem::is_regular_file(fileStatus)) {
        result.skipped = true;
        result.error = "No es un archivo regular";
        return result;
    }

    auto fileSize = std::filesystem::file_size(filePath, ec);
    if (ec) {
        result.skipped = true;
        result.error = "No se pudo determinar el tamaño del archivo";
        return result;
    }

    if (fileSize > m_config.maxFileSizeBytes) {
        result.skipped = true;
        result.error = "Archivo excede el límite máximo configurado";
        return result;
    }

    // 2. Cálculo unificado de hashes (SHA-256, SHA-1, MD5) en una sola pasada de I/O
    FileHashes hashes = CryptoUtils::computeFileHashes(filePath, m_config.bufferSizeBytes);
    if (!hashes.success) {
        result.skipped = true;
        result.error = "Error de lectura al computar hashes criptográficos";
        return result;
    }

    result.sha256 = hashes.sha256;
    result.sha1   = hashes.sha1;
    result.md5    = hashes.md5;

    // 3. Cotejo contra la base de datos de firmas (SQLite)
    if (m_sigDb && m_sigDb->isOpen()) {
        auto match = m_sigDb->lookup(result.sha256, result.sha1, result.md5);
        if (match.has_value()) {
            int score = 75; // Puntuación predeterminada alta
            if (match->severity == "critical") score = 100;
            else if (match->severity == "high") score = 80;
            else if (match->severity == "medium") score = 50;
            else if (match->severity == "low") score = 25;

            // Una coincidencia exacta de hash es siempre una detección confirmada: nunca debe
            // quedar por debajo del umbral de amenaza aunque la severidad registrada sea baja.
            score = std::max(score, 61);

            result.addThreat(
                match->malwareName,
                "hash_signature",
                match->severity,
                score,
                "Coincidencia exacta de hash en la base de datos"
            );
        }
    }

    // 4. Heurística de doble extensión sospechosa (ej: "documento.pdf.exe")
    if (m_config.checkDoubleExtensions && hasDoubleExtension(filePath)) {
        result.addThreat(
            "Heuristic.DoubleExtension",
            "heuristic",
            "medium",
            40,
            "El archivo utiliza una extensión doble potencialmente engañosa"
        );
    }

    // 4b. Reglas YARA (primeros 4 MB del contenido)
    if (m_yara && m_yara->ruleCount() > 0 && fileSize > 0) {
        std::ifstream in(filePath, std::ios::binary);
        if (in.is_open()) {
            std::vector<uint8_t> head(std::min<size_t>(static_cast<size_t>(fileSize), 4 * 1024 * 1024));
            in.read(reinterpret_cast<char*>(head.data()), static_cast<std::streamsize>(head.size()));
            head.resize(static_cast<size_t>(in.gcount()));
            for (const auto& m : m_yara->scan(head.data(), head.size())) {
                int yScore = 45;
                if (m.severity == "critical") yScore = 85;
                else if (m.severity == "high") yScore = 70;
                else if (m.severity == "low") yScore = 20;
                result.addThreat("YARA." + m.rule, "yara", m.severity, yScore, m.description);
            }
        }
    }

    // 5. Análisis heurístico profundo de PE y scripts
    if (m_heuristics) {
        ScanResult heurResult = m_heuristics->evaluate(filePath);
        for (const auto& th : heurResult.threats) {
            result.addThreat(th.name, th.method, th.severity, th.score, th.details);
        }
    }

    auto tEnd = std::chrono::high_resolution_clock::now();
    result.scanTimeMs = std::chrono::duration<double, std::milli>(tEnd - tStart).count();

    return result;
}

bool FileScanner::hasDoubleExtension(const std::filesystem::path& path) {
    static const std::unordered_set<std::string> dangerousExts = {
        ".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"
    };

    static const std::unordered_set<std::string> decoyExts = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png", ".zip"
    };

    std::string ext = paths::extensionLower(path);
    if (dangerousExts.find(ext) == dangerousExts.end()) {
        return false;
    }

    std::filesystem::path stemPath = path.stem();
    std::string innerExt = paths::extensionLower(stemPath);

    return decoyExts.find(innerExt) != decoyExts.end();
}

ScanSessionStats FileScanner::scanPath(
    const std::filesystem::path& targetPath,
    ScanType type,
    std::function<void(const ScanResult&)> progressCallback
) {
    return scanPaths(std::vector<std::filesystem::path>{targetPath}, type, progressCallback);
}

ScanSessionStats FileScanner::scanPaths(
    const std::vector<std::filesystem::path>& targetPaths,
    ScanType type,
    std::function<void(const ScanResult&)> progressCallback
) {
    namespace fs = std::filesystem;

    m_cancelRequested = false;
    ScanSessionStats session;
    session.scanType = type;

    auto startClock = std::chrono::high_resolution_clock::now();

    // Comprueba si una ruta cae dentro de algún directorio excluido de la configuración
    auto isExcluded = [this](const fs::path& p) {
        for (const auto& ex : m_config.excludedPaths) {
            const fs::path rel = p.lexically_relative(ex);
            if (!rel.empty() && *rel.begin() != "..") return true;
        }
        return false;
    };

    // Los archivos se procesan por lotes: así un escaneo completo (millones de archivos)
    // no acumula todas las tareas y resultados en memoria.
    constexpr size_t kBatchSize = 512;
    std::vector<fs::path> batch;
    batch.reserve(kBatchSize);

    auto flushBatch = [&]() {
        std::vector<std::future<ScanResult>> futures;
        futures.reserve(batch.size());

        for (const auto& fPath : batch) {
            futures.push_back(m_threadPool->enqueue([this, fPath]() {
                return this->scanFile(fPath);
            }));
        }
        batch.clear();

        // Siempre se esperan todas las tareas del lote, incluso si se canceló, para no dejar
        // trabajos en vuelo que referencien objetos que podrían destruirse tras retornar.
        for (auto& fut : futures) {
            try {
                ScanResult res = fut.get();
                if (res.skipped) {
                    session.filesSkipped++;
                } else {
                    session.filesScanned++;
                    if (res.isThreat()) {
                        session.threatsFound++;
                    }
                }

                if (progressCallback) {
                    progressCallback(res);
                }

                if (m_config.keepCleanResults || res.riskScore > 0) {
                    session.results.push_back(std::move(res));
                }
            } catch (...) {
                session.filesSkipped++;
            }
        }
    };

    for (const auto& basePath : targetPaths) {
        if (m_cancelRequested) break;

        std::error_code ec;
        const auto st = fs::status(basePath, ec);
        if (ec || !fs::exists(st)) continue;

        if (fs::is_regular_file(st)) {
            batch.push_back(basePath);
            if (batch.size() >= kBatchSize) flushBatch();
            continue;
        }
        if (!fs::is_directory(st)) continue;

        fs::recursive_directory_iterator it(basePath, fs::directory_options::skip_permission_denied, ec);
        const fs::recursive_directory_iterator endIt;

        while (!ec && it != endIt) {
            if (m_cancelRequested) break;

            std::error_code entryEc;
            const bool isLink = it->is_symlink(entryEc);

            if (!isLink && it->is_directory(entryEc)) {
                if (isExcluded(it->path())) it.disable_recursion_pending();
            } else if (!isLink && it->is_regular_file(entryEc)) {
                batch.push_back(it->path());
                if (batch.size() >= kBatchSize) flushBatch();
            }

            it.increment(ec);
        }
    }

    if (!batch.empty()) flushBatch();

    auto endClock = std::chrono::high_resolution_clock::now();
    session.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endClock - startClock);

    return session;
}

std::vector<std::filesystem::path> FileScanner::getFixedDrives() {
    std::vector<std::filesystem::path> drives;
    const DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if ((mask & (1u << i)) == 0) continue;
        const wchar_t root[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', L'\0' };
        if (GetDriveTypeW(root) == DRIVE_FIXED) {
            drives.emplace_back(root);
        }
    }
    return drives;
}

} // namespace openguard
