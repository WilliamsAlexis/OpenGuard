/**
 * @file quarantine.cpp
 * @brief Implementación de la bóveda de cuarentena cifrada con AES-256 (BCrypt/CNG).
 * @details Este módulo aísla amenazas impidiendo su ejecución, cifra los binarios usando
 *          AES-256 en modo CBC con padding PKCS#7 y destruye el archivo original con
 *          sobrescritura criptográfica aleatoria.
 */

#include "openguard/quarantine.h"
#include "openguard/crypto_utils.h"

#include <windows.h>
#include <bcrypt.h>
#include <sqlite3.h>

#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace openguard {

namespace {

constexpr char VAULT_MAGIC[4] = {'O', 'G', 'Q', 'B'}; // OpenGuard Quarantine Binary

/**
 * @brief Genera un identificador único pseudoaleatorio (QID) para el elemento.
 * @param path Ruta del archivo.
 * @return Cadena hexadecimal de 16 caracteres.
 */
std::string generateQID(const std::filesystem::path& path) {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::string seed = path.string() + std::to_string(now);
    return CryptoUtils::computeSha256FromBuffer(seed.data(), seed.size()).substr(0, 16);
}

/**
 * @brief Obtiene la fecha y hora actual en formato ISO-8601 UTC.
 * @return Cadena con la fecha ISO-8601.
 */
std::string getCurrentIsoTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm gm{};
    gmtime_s(&gm, &tt);

    std::ostringstream oss;
    oss << std::put_time(&gm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace anónimo

QuarantineVault::QuarantineVault(const std::filesystem::path& vaultDir)
    : m_vaultDir(vaultDir),
      m_filesDir(vaultDir / "files"),
      m_dbPath(vaultDir / "quarantine.db"),
      m_keyPath(vaultDir / ".vault.key") {

    std::error_code ec;
    std::filesystem::create_directories(m_filesDir, ec);

    initializeKey();
    initializeDatabase();
}

QuarantineVault::~QuarantineVault() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dbHandle) {
        sqlite3_close_v2(m_dbHandle);
        m_dbHandle = nullptr;
    }
}

void QuarantineVault::initializeKey() {
    if (std::filesystem::exists(m_keyPath)) {
        std::ifstream kFile(m_keyPath, std::ios::binary);
        if (kFile.is_open()) {
            m_aesKey.resize(32); // Clave AES de 256 bits (32 bytes)
            kFile.read(reinterpret_cast<char*>(m_aesKey.data()), 32);
            if (kFile.gcount() == 32) {
                return;
            }
        }
    }

    // Generar nueva clave criptográfica aleatoria mediante BCryptGenRandom
    m_aesKey.resize(32);
    BCryptGenRandom(nullptr, m_aesKey.data(), static_cast<ULONG>(m_aesKey.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    std::ofstream kFile(m_keyPath, std::ios::binary | std::ios::trunc);
    if (kFile.is_open()) {
        kFile.write(reinterpret_cast<const char*>(m_aesKey.data()), m_aesKey.size());
    }

    // Ocultar el archivo de clave en Windows
    SetFileAttributesW(m_keyPath.wstring().c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

void QuarantineVault::initializeDatabase() {
    std::string pathUtf8 = m_dbPath.string();
    int rc = sqlite3_open_v2(
        pathUtf8.c_str(),
        &m_dbHandle,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc == SQLITE_OK && m_dbHandle) {
        const char* ddl =
            "CREATE TABLE IF NOT EXISTS quarantine_items ("
            "    qid            TEXT PRIMARY KEY,"
            "    original_path  TEXT NOT NULL,"
            "    threat_name    TEXT NOT NULL,"
            "    severity       TEXT DEFAULT 'high',"
            "    sha256         TEXT NOT NULL,"
            "    quarantined_at TEXT NOT NULL,"
            "    size_bytes     INTEGER NOT NULL,"
            "    enc_file_name  TEXT NOT NULL"
            ");";
        sqlite3_exec(m_dbHandle, ddl, nullptr, nullptr, nullptr);
    }
}

void QuarantineVault::secureDeleteFile(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(path, ec);
    if (!ec && fileSize > 0) {
        // Sobrescritura con bytes aleatorios antes de la eliminación física
        HANDLE hFile = CreateFileW(
            path.wstring().c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH,
            nullptr
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            std::vector<BYTE> randomBuf(65536);
            DWORD bytesWritten = 0;
            size_t remaining = fileSize;

            while (remaining > 0) {
                DWORD toWrite = static_cast<DWORD>(std::min<size_t>(remaining, randomBuf.size()));
                BCryptGenRandom(nullptr, randomBuf.data(), toWrite, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                WriteFile(hFile, randomBuf.data(), toWrite, &bytesWritten, nullptr);
                if (bytesWritten == 0) break;
                remaining -= bytesWritten;
            }

            FlushFileBuffers(hFile);
            CloseHandle(hFile);
        }
    }

    // Eliminación final del sistema de archivos
    std::filesystem::remove(path, ec);
}

std::optional<QuarantineItem> QuarantineVault::quarantineFile(
    const std::filesystem::path& filePath,
    const std::string& threatName,
    const std::string& severity,
    std::string sha256
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle || m_aesKey.size() != 32) return std::nullopt;

    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec) || !std::filesystem::is_regular_file(filePath, ec)) {
        return std::nullopt;
    }

    // 1. Leer contenido completo del archivo original
    std::ifstream src(filePath, std::ios::binary | std::ios::ate);
    if (!src.is_open()) return std::nullopt;

    size_t fileSize = static_cast<size_t>(src.tellg());
    src.seekg(0, std::ios::beg);

    std::vector<uint8_t> plainData(fileSize);
    if (!src.read(reinterpret_cast<char*>(plainData.data()), fileSize)) {
        return std::nullopt;
    }
    src.close();

    if (sha256.empty()) {
        sha256 = CryptoUtils::computeSha256FromBuffer(plainData.data(), plainData.size());
    }

    // 2. Cifrado simétrico AES-256-CBC con Windows CNG
    BCRYPT_ALG_HANDLE hAes = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) return std::nullopt;

    BCryptSetProperty(
        hAes,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );

    // Vector de Inicialización (IV) de 16 bytes único por archivo
    std::vector<uint8_t> iv(16);
    BCryptGenRandom(nullptr, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(
        hAes,
        &hKey,
        nullptr,
        0,
        m_aesKey.data(),
        static_cast<ULONG>(m_aesKey.size()),
        0
    );

    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAes, 0);
        return std::nullopt;
    }

    // Determinar tamaño de búfer de salida requerido para cifrado con padding
    DWORD cipherLen = 0;
    std::vector<uint8_t> ivCopy = iv;
    status = BCryptEncrypt(
        hKey,
        plainData.data(),
        static_cast<ULONG>(plainData.size()),
        nullptr,
        ivCopy.data(),
        static_cast<ULONG>(ivCopy.size()),
        nullptr,
        0,
        &cipherLen,
        BCRYPT_BLOCK_PADDING
    );

    if (!NT_SUCCESS(status) || cipherLen == 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAes, 0);
        return std::nullopt;
    }

    std::vector<uint8_t> cipherData(cipherLen);
    ivCopy = iv;
    status = BCryptEncrypt(
        hKey,
        plainData.data(),
        static_cast<ULONG>(plainData.size()),
        nullptr,
        ivCopy.data(),
        static_cast<ULONG>(ivCopy.size()),
        cipherData.data(),
        cipherLen,
        &cipherLen,
        BCRYPT_BLOCK_PADDING
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);

    if (!NT_SUCCESS(status)) return std::nullopt;

    // 3. Escribir archivo cifrado en la bóveda (.qbin)
    std::string qid = generateQID(filePath);
    std::string encFileName = qid + ".qbin";
    std::filesystem::path encFilePath = m_filesDir / encFileName;

    std::ofstream outEnc(encFilePath, std::ios::binary | std::ios::trunc);
    if (!outEnc.is_open()) return std::nullopt;

    // Cabecera: Magic (4B) + OriginalSize (8B) + IV (16B) + Cifrado
    outEnc.write(VAULT_MAGIC, 4);
    uint64_t origSize64 = static_cast<uint64_t>(fileSize);
    outEnc.write(reinterpret_cast<const char*>(&origSize64), sizeof(origSize64));
    outEnc.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    outEnc.write(reinterpret_cast<const char*>(cipherData.data()), cipherData.size());
    outEnc.close();

    // 4. Registrar metadatos en la base de datos de cuarentena
    QuarantineItem item;
    item.qid = qid;
    item.originalPath = filePath;
    item.threatName = threatName;
    item.severity = severity;
    item.sha256 = sha256;
    item.quarantinedAt = getCurrentIsoTime();
    item.sizeBytes = fileSize;
    item.encryptedFileName = encFileName;

    const char* insSql =
        "INSERT INTO quarantine_items (qid, original_path, threat_name, severity, sha256, quarantined_at, size_bytes, enc_file_name) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, insSql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::string origPathStr = item.originalPath.string();
        sqlite3_bind_text(stmt, 1, item.qid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, origPathStr.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, item.threatName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, item.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, item.sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, item.quarantinedAt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(item.sizeBytes));
        sqlite3_bind_text(stmt, 8, item.encryptedFileName.c_str(), -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // 5. Destrucción segura del archivo original infectado
    secureDeleteFile(filePath);

    return item;
}

bool QuarantineVault::restoreFile(const std::string& qid, const std::filesystem::path& destinationPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle || m_aesKey.size() != 32) return false;

    // 1. Obtener metadatos desde la base de datos
    std::string origPath;
    std::string encFileName;

    const char* sql = "SELECT original_path, enc_file_name FROM quarantine_items WHERE qid = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, qid.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        origPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        encFileName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    }
    sqlite3_finalize(stmt);

    if (origPath.empty() || encFileName.empty()) return false;

    // 2. Leer archivo cifrado de la bóveda
    std::filesystem::path encPath = m_filesDir / encFileName;
    std::ifstream inEnc(encPath, std::ios::binary);
    if (!inEnc.is_open()) return false;

    char magic[4]{};
    inEnc.read(magic, 4);
    if (std::memcmp(magic, VAULT_MAGIC, 4) != 0) return false;

    uint64_t origSize = 0;
    inEnc.read(reinterpret_cast<char*>(&origSize), sizeof(origSize));

    std::vector<uint8_t> iv(16);
    inEnc.read(reinterpret_cast<char*>(iv.data()), 16);

    std::vector<uint8_t> cipherData((std::istreambuf_iterator<char>(inEnc)),
                                    std::istreambuf_iterator<char>());
    inEnc.close();

    // 3. Descifrar con BCrypt
    BCRYPT_ALG_HANDLE hAes = nullptr;
    BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(
        hAes,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );

    BCRYPT_KEY_HANDLE hKey = nullptr;
    BCryptGenerateSymmetricKey(hAes, &hKey, nullptr, 0, m_aesKey.data(), static_cast<ULONG>(m_aesKey.size()), 0);

    DWORD plainLen = 0;
    std::vector<uint8_t> ivCopy = iv;
    BCryptDecrypt(
        hKey,
        cipherData.data(),
        static_cast<ULONG>(cipherData.size()),
        nullptr,
        ivCopy.data(),
        16,
        nullptr,
        0,
        &plainLen,
        BCRYPT_BLOCK_PADDING
    );

    std::vector<uint8_t> plainData(plainLen);
    ivCopy = iv;
    NTSTATUS status = BCryptDecrypt(
        hKey,
        cipherData.data(),
        static_cast<ULONG>(cipherData.size()),
        nullptr,
        ivCopy.data(),
        16,
        plainData.data(),
        plainLen,
        &plainLen,
        BCRYPT_BLOCK_PADDING
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);

    if (!NT_SUCCESS(status)) return false;

    // Truncar al tamaño original si el padding agregó bytes adicionales
    if (origSize > 0 && origSize < plainData.size()) {
        plainData.resize(static_cast<size_t>(origSize));
    }

    // 4. Restaurar en destino
    std::filesystem::path target = destinationPath.empty() ? std::filesystem::path(origPath) : destinationPath;
    if (target.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(target.parent_path(), ec);
    }

    std::ofstream outPlain(target, std::ios::binary | std::ios::trunc);
    if (!outPlain.is_open()) return false;
    outPlain.write(reinterpret_cast<const char*>(plainData.data()), plainData.size());
    outPlain.close();

    // 5. Eliminar de la cuarentena
    std::error_code ec;
    std::filesystem::remove(encPath, ec);

    sqlite3_stmt* delStmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, "DELETE FROM quarantine_items WHERE qid = ?;", -1, &delStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(delStmt, 1, qid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(delStmt);
        sqlite3_finalize(delStmt);
    }

    return true;
}

bool QuarantineVault::deletePermanently(const std::string& qid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return false;

    std::string encFileName;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, "SELECT enc_file_name FROM quarantine_items WHERE qid = ? LIMIT 1;", -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, qid.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            encFileName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }

    if (encFileName.empty()) return false;

    // Borrado seguro del blob cifrado
    secureDeleteFile(m_filesDir / encFileName);

    sqlite3_stmt* delStmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, "DELETE FROM quarantine_items WHERE qid = ?;", -1, &delStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(delStmt, 1, qid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(delStmt);
        sqlite3_finalize(delStmt);
    }

    return true;
}

std::vector<QuarantineItem> QuarantineVault::listItems() {
    std::vector<QuarantineItem> items;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return items;

    const char* sql = "SELECT qid, original_path, threat_name, severity, sha256, quarantined_at, size_bytes, enc_file_name FROM quarantine_items;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            QuarantineItem item;
            item.qid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            item.originalPath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            item.threatName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            item.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            item.sha256 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            item.quarantinedAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            item.sizeBytes = static_cast<size_t>(sqlite3_column_int64(stmt, 6));
            item.encryptedFileName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
            items.push_back(item);
        }
        sqlite3_finalize(stmt);
    }
    return items;
}

size_t QuarantineVault::getItemCount() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle) return 0;

    size_t count = 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, "SELECT COUNT(*) FROM quarantine_items;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }
    return count;
}

} // namespace openguard

