/**
 * @file scanner.cpp
 * @brief Implementación del motor de escaneo multihilo y cotejo de firmas.
 * @details Este módulo ejecuta la inspección concurrente de archivos sobre el sistema de archivos
 *          de Windows con soporte de exclusión de enlaces simbólicos conflictivos y tolerancia a fallos.
 */

#include "openguard/scanner.h"
#include "openguard/crypto_utils.h"

#include <chrono>
#include <unordered_set>
#include <iostream>

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
    m_threadPool = std::make_unique<ThreadPool>(m_config.threadCount);
    m_heuristics = std::make_unique<HeuristicsEngine>();
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

    std::string ext = toLowerStr(path.extension().string());
    if (dangerousExts.find(ext) == dangerousExts.end()) {
        return false;
    }

    std::filesystem::path stemPath = path.stem();
    std::string innerExt = toLowerStr(stemPath.extension().string());

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
    m_cancelRequested = false;
    ScanSessionStats session;
    session.scanType = type;

    auto startClock = std::chrono::high_resolution_clock::now();

    // 1. Recolección de archivos a escanear (recursiva y con tolerancia a rutas protegidas)
    std::vector<std::filesystem::path> filesToScan;

    for (const auto& basePath : targetPaths) {
        if (m_cancelRequested) break;

        std::error_code ec;
        if (!std::filesystem::exists(basePath, ec)) continue;

        if (std::filesystem::is_regular_file(basePath, ec)) {
            filesToScan.push_back(basePath);
        } else if (std::filesystem::is_directory(basePath, ec)) {
            auto itOptions = std::filesystem::directory_options::skip_permission_denied;
            for (auto it = std::filesystem::recursive_directory_iterator(basePath, itOptions, ec);
                 it != std::filesystem::recursive_directory_iterator();
                 it.increment(ec)) {
                if (ec) {
                    ec.clear();
                    continue;
                }
                if (m_cancelRequested) break;

                if (it->is_regular_file(ec) && !it->is_symlink(ec)) {
                    filesToScan.push_back(it->path());
                }
            }
        }
    }

    // 2. Procesamiento multihilo paralelo
    std::mutex resultsMutex;
    std::vector<std::future<ScanResult>> futures;
    futures.reserve(filesToScan.size());

    for (const auto& fPath : filesToScan) {
        if (m_cancelRequested) break;

        futures.push_back(m_threadPool->enqueue([this, fPath]() {
            return this->scanFile(fPath);
        }));
    }

    for (auto& fut : futures) {
        if (m_cancelRequested) break;

        try {
            ScanResult res = fut.get();
            {
                std::lock_guard<std::mutex> lock(resultsMutex);
                if (res.skipped) {
                    session.filesSkipped++;
                } else {
                    session.filesScanned++;
                    if (res.isThreat()) {
                        session.threatsFound++;
                    }
                }
                session.results.push_back(res);
            }

            if (progressCallback) {
                progressCallback(res);
            }
        } catch (...) {
            std::lock_guard<std::mutex> lock(resultsMutex);
            session.filesSkipped++;
        }
    }

    auto endClock = std::chrono::high_resolution_clock::now();
    session.duration = std::chrono::duration_cast<std::chrono::milliseconds>(endClock - startClock);

    return session;
}

} // namespace openguard

