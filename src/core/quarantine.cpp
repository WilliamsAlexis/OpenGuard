/**
 * @file quarantine.cpp
 * @brief Implementación de la bóveda de cuarentena cifrada con AES-256 (BCrypt/CNG).
 * @details Este módulo aísla amenazas impidiendo su ejecución, cifra los binarios usando
 *          AES-256 en modo CBC con padding PKCS#7 y destruye el archivo original con
 *          sobrescritura criptográfica aleatoria.
 */

#include "openguard/quarantine.h"
#include "openguard/crypto_utils.h"
#include "openguard/paths.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <dpapi.h>
#include <sqlite3.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <chrono>
#include <iterator>
#include <optional>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
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
    std::string seed = paths::toUtf8(path) + std::to_string(now); // UTF-8: path.string() puede fallar con caracteres no ANSI
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

/**
 * @brief Lee una columna de texto de SQLite devolviendo cadena vacía si es NULL.
 */
std::string columnText(sqlite3_stmt* stmt, int col) {
    const unsigned char* txt = sqlite3_column_text(stmt, col);
    return txt ? std::string(reinterpret_cast<const char*>(txt)) : std::string();
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
    constexpr size_t kKeySize = 32; // Clave AES de 256 bits
    std::error_code ec;

    // 1. Intentar cargar la clave existente (protegida con DPAPI a nivel de equipo)
    if (std::filesystem::exists(m_keyPath, ec)) {
        std::ifstream kFile(m_keyPath, std::ios::binary);
        if (kFile.is_open()) {
            std::vector<uint8_t> blob((std::istreambuf_iterator<char>(kFile)),
                                      std::istreambuf_iterator<char>());
            kFile.close();

            if (!blob.empty()) {
                DATA_BLOB in{};
                in.cbData = static_cast<DWORD>(blob.size());
                in.pbData = blob.data();
                DATA_BLOB out{};

                if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) {
                    if (out.cbData == kKeySize) {
                        m_aesKey.assign(out.pbData, out.pbData + kKeySize);
                    }
                    SecureZeroMemory(out.pbData, out.cbData);
                    LocalFree(out.pbData);
                    if (m_aesKey.size() == kKeySize) return;
                    m_aesKey.clear();
                } else if (blob.size() == kKeySize) {
                    // Formato heredado (clave en claro de versiones previas): se reutiliza y se
                    // reescribe protegida más abajo para no perder acceso a los elementos aislados.
                    m_aesKey = blob;
                } else {
                    // Blob ilegible (otro equipo o corrupción): conservarlo antes de crear una clave nueva.
                    SetFileAttributesW(m_keyPath.wstring().c_str(), FILE_ATTRIBUTE_NORMAL);
                    std::filesystem::rename(m_keyPath, m_keyPath.wstring() + L".bak", ec);
                }
            }
        }
    }

    // 2. Generar nueva clave aleatoria mediante BCryptGenRandom si no hay una válida
    if (m_aesKey.size() != kKeySize) {
        m_aesKey.assign(kKeySize, 0);
        BCryptGenRandom(nullptr, m_aesKey.data(), static_cast<ULONG>(m_aesKey.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    }

    // 3. Persistir la clave cifrada con DPAPI (CRYPTPROTECT_LOCAL_MACHINE permite al servicio y al CLI compartirla)
    DATA_BLOB plain{};
    plain.cbData = static_cast<DWORD>(m_aesKey.size());
    plain.pbData = m_aesKey.data();
    DATA_BLOB protectedBlob{};

    std::vector<uint8_t> toWrite;
    if (CryptProtectData(&plain, L"OpenGuard Quarantine Key", nullptr, nullptr, nullptr,
                         CRYPTPROTECT_LOCAL_MACHINE, &protectedBlob)) {
        toWrite.assign(protectedBlob.pbData, protectedBlob.pbData + protectedBlob.cbData);
        LocalFree(protectedBlob.pbData);
    } else {
        toWrite = m_aesKey; // DPAPI no disponible: último recurso
    }

    // Un archivo oculto/de sistema no puede sobrescribirse directamente: restablecer atributos primero
    SetFileAttributesW(m_keyPath.wstring().c_str(), FILE_ATTRIBUTE_NORMAL);
    {
        std::ofstream kFile(m_keyPath, std::ios::binary | std::ios::trunc);
        if (kFile.is_open()) {
            kFile.write(reinterpret_cast<const char*>(toWrite.data()), static_cast<std::streamsize>(toWrite.size()));
        }
    }
    SetFileAttributesW(m_keyPath.wstring().c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

void QuarantineVault::initializeDatabase() {
    const std::string pathUtf8 = paths::toUtf8(m_dbPath); // SQLite exige UTF-8
    int rc = sqlite3_open_v2(
        pathUtf8.c_str(),
        &m_dbHandle,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (rc == SQLITE_OK && m_dbHandle) {
        sqlite3_busy_timeout(m_dbHandle, 5000);
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
    outEnc.write(reinterpret_cast<const char*>(iv.data()), static_cast<std::streamsize>(iv.size()));
    outEnc.write(reinterpret_cast<const char*>(cipherData.data()), static_cast<std::streamsize>(cipherData.size()));
    outEnc.flush();
    const bool writeOk = outEnc.good();
    outEnc.close();
    if (!writeOk) {
        std::filesystem::remove(encFilePath, ec);
        return std::nullopt; // Disco lleno u otro error: el archivo original NO se destruye
    }

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

    bool recorded = false;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, insSql, -1, &stmt, nullptr) == SQLITE_OK) {
        // La ruta se guarda en UTF-8 para conservar caracteres no ASCII
        const auto origPathU8 = item.originalPath.u8string();
        const std::string origPathStr(reinterpret_cast<const char*>(origPathU8.data()), origPathU8.size());
        sqlite3_bind_text(stmt, 1, item.qid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, origPathStr.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, item.threatName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, item.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, item.sha256.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, item.quarantinedAt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(item.sizeBytes));
        sqlite3_bind_text(stmt, 8, item.encryptedFileName.c_str(), -1, SQLITE_TRANSIENT);

        recorded = (sqlite3_step(stmt) == SQLITE_DONE);
        sqlite3_finalize(stmt);
    }

    if (!recorded) {
        // Sin registro no habría forma de restaurar: se revierte y se conserva el original
        std::filesystem::remove(encFilePath, ec);
        return std::nullopt;
    }

    // 5. Destrucción segura del archivo original infectado
    secureDeleteFile(filePath);

    return item;
}

bool QuarantineVault::restoreFile(const std::string& qid, const std::filesystem::path& destinationPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dbHandle || m_aesKey.size() != 32) return false;

    // 1. Obtener metadatos desde la base de datos
    std::string origPathStr;
    std::string encFileName;
    std::string expectedSha256;

    const char* sql = "SELECT original_path, enc_file_name, sha256 FROM quarantine_items WHERE qid = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_dbHandle, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, qid.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        origPathStr = columnText(stmt, 0);
        encFileName = columnText(stmt, 1);
        expectedSha256 = columnText(stmt, 2);
    }
    sqlite3_finalize(stmt);

    if (origPathStr.empty() || encFileName.empty()) return false;

    // Impedir que un registro manipulado apunte fuera de la bóveda (path traversal)
    if (encFileName.find_first_of("\\/:") != std::string::npos) return false;

    const std::filesystem::path origPath(
        std::u8string(reinterpret_cast<const char8_t*>(origPathStr.data()), origPathStr.size()));

    // 2. Leer archivo cifrado de la bóveda
    std::filesystem::path encPath = m_filesDir / encFileName;
    std::ifstream inEnc(encPath, std::ios::binary);
    if (!inEnc.is_open()) return false;

    char magic[4]{};
    inEnc.read(magic, 4);
    if (inEnc.gcount() != 4 || std::memcmp(magic, VAULT_MAGIC, 4) != 0) return false;

    uint64_t origSize = 0;
    inEnc.read(reinterpret_cast<char*>(&origSize), sizeof(origSize));

    std::vector<uint8_t> iv(16);
    inEnc.read(reinterpret_cast<char*>(iv.data()), 16);
    if (inEnc.gcount() != 16) return false;

    std::vector<uint8_t> cipherData((std::istreambuf_iterator<char>(inEnc)),
                                    std::istreambuf_iterator<char>());
    inEnc.close();
    if (cipherData.empty() || cipherData.size() % 16 != 0) return false;

    // 3. Descifrar con BCrypt
    BCRYPT_ALG_HANDLE hAes = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, nullptr, 0))) return false;
    BCryptSetProperty(
        hAes,
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAes, &hKey, nullptr, 0, m_aesKey.data(),
                                               static_cast<ULONG>(m_aesKey.size()), 0))) {
        BCryptCloseAlgorithmProvider(hAes, 0);
        return false;
    }

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

    // El descifrado devuelve el padding PKCS#7 ya eliminado; se ajusta al tamaño original registrado
    if (plainLen < plainData.size()) plainData.resize(plainLen);
    if (origSize < plainData.size()) {
        plainData.resize(static_cast<size_t>(origSize));
    }

    // Verificación de integridad (CBC no autentica por sí mismo): el hash debe coincidir con el original
    if (!expectedSha256.empty()) {
        const std::string actual = plainData.empty()
            ? CryptoUtils::computeSha256FromBuffer("", 0)
            : CryptoUtils::computeSha256FromBuffer(plainData.data(), plainData.size());
        if (!actual.empty() && actual != expectedSha256) return false;
    }

    // 4. Restaurar en destino (sin sobrescribir archivos existentes)
    std::error_code ec;
    std::filesystem::path target = destinationPath.empty() ? origPath : destinationPath;
    if (std::filesystem::exists(target, ec)) return false;
    if (target.has_parent_path()) {
        std::filesystem::create_directories(target.parent_path(), ec);
    }

    std::ofstream outPlain(target, std::ios::binary | std::ios::trunc);
    if (!outPlain.is_open()) return false;
    outPlain.write(reinterpret_cast<const char*>(plainData.data()), static_cast<std::streamsize>(plainData.size()));
    outPlain.flush();
    const bool restoreOk = outPlain.good();
    outPlain.close();
    if (!restoreOk) {
        std::filesystem::remove(target, ec);
        return false;
    }

    // 5. Eliminar de la cuarentena
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
            encFileName = columnText(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (encFileName.empty()) return false;
    if (encFileName.find_first_of("\\/:") != std::string::npos) return false; // Evitar path traversal

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
            item.qid = columnText(stmt, 0);
            const std::string pathU8 = columnText(stmt, 1);
            item.originalPath = std::filesystem::path(
                std::u8string(reinterpret_cast<const char8_t*>(pathU8.data()), pathU8.size()));
            item.threatName = columnText(stmt, 2);
            item.severity = columnText(stmt, 3);
            item.sha256 = columnText(stmt, 4);
            item.quarantinedAt = columnText(stmt, 5);
            item.sizeBytes = static_cast<size_t>(sqlite3_column_int64(stmt, 6));
            item.encryptedFileName = columnText(stmt, 7);
            items.push_back(std::move(item));
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

