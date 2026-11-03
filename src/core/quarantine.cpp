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
#include <cctype>
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

// ---------------------------------------------------------------------------------------------
// Formatos de la bóveda
//   v1 (heredado): "OGQB" | tamaño(8) | IV(16) | AES-256-CBC
//   v2 (actual)  : "OGQ2" | tamaño(8) | nonce(12) | etiqueta(16) | AES-256-GCM (autenticado)
// En v2 la cabecera de 12 bytes se autentica como datos adicionales (AAD): cualquier manipulación
// del contenido o del tamaño registrado hace fallar el descifrado.
// ---------------------------------------------------------------------------------------------
static constexpr char VAULT_MAGIC_V2[4] = {'O', 'G', 'Q', '2'};
static constexpr size_t kGcmNonceSize = 12;
static constexpr size_t kGcmTagSize = 16;
static constexpr size_t kGcmHeaderSize = 4 + 8 + kGcmNonceSize + kGcmTagSize;
static constexpr uint64_t kMaxQuarantineBytes = 512ull * 1024ull * 1024ull;

namespace {

/// Abre AES-256 en el modo de encadenamiento indicado y genera la clave simétrica.
bool openAesKey(const std::vector<uint8_t>& key, const wchar_t* mode, ULONG modeBytes,
                BCRYPT_ALG_HANDLE& hAlg, BCRYPT_KEY_HANDLE& hKey) {
    hAlg = nullptr;
    hKey = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) return false;
    if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                      reinterpret_cast<PBYTE>(const_cast<wchar_t*>(mode)), modeBytes, 0)) ||
        !NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, const_cast<PUCHAR>(key.data()),
                                               static_cast<ULONG>(key.size()), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = nullptr;
        return false;
    }
    return true;
}

void closeAes(BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hKey) {
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}

bool gcmEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& aad, std::vector<uint8_t>& nonce,
                const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher, std::vector<uint8_t>& tag) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!openAesKey(key, BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), hAlg, hKey)) return false;

    nonce.assign(kGcmNonceSize, 0);
    BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    tag.assign(kGcmTagSize, 0);
    cipher.assign(plain.size(), 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce.data();
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = const_cast<PUCHAR>(aad.data());
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());

    ULONG written = 0;
    uint8_t dummy = 0;
    const NTSTATUS st = BCryptEncrypt(hKey, plain.empty() ? &dummy : const_cast<PUCHAR>(plain.data()),
                                      static_cast<ULONG>(plain.size()), &info, nullptr, 0,
                                      cipher.empty() ? &dummy : cipher.data(), static_cast<ULONG>(cipher.size()), &written, 0);
    closeAes(hAlg, hKey);
    return NT_SUCCESS(st);
}

/// Descifra un blob v2. Devuelve false si la etiqueta de autenticación no coincide (archivo manipulado).
bool gcmDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& blob, std::vector<uint8_t>& plain) {
    if (blob.size() < kGcmHeaderSize) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!openAesKey(key, BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), hAlg, hKey)) return false;

    std::vector<uint8_t> aad(blob.begin(), blob.begin() + 12);
    std::vector<uint8_t> nonce(blob.begin() + 12, blob.begin() + 12 + kGcmNonceSize);
    std::vector<uint8_t> tag(blob.begin() + 12 + kGcmNonceSize, blob.begin() + kGcmHeaderSize);
    std::vector<uint8_t> cipher(blob.begin() + kGcmHeaderSize, blob.end());
    plain.assign(cipher.size(), 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = nonce.data();
    info.cbNonce = static_cast<ULONG>(nonce.size());
    info.pbAuthData = aad.data();
    info.cbAuthData = static_cast<ULONG>(aad.size());
    info.pbTag = tag.data();
    info.cbTag = static_cast<ULONG>(tag.size());

    ULONG written = 0;
    uint8_t dummy = 0;
    const NTSTATUS st = BCryptDecrypt(hKey, cipher.empty() ? &dummy : cipher.data(), static_cast<ULONG>(cipher.size()),
                                      &info, nullptr, 0, plain.empty() ? &dummy : plain.data(),
                                      static_cast<ULONG>(plain.size()), &written, 0);
    closeAes(hAlg, hKey);
    if (!NT_SUCCESS(st)) return false;
    plain.resize(written);
    return true;
}

/// Descifrado del formato v1 (AES-256-CBC con relleno PKCS#7), conservado para leer bóvedas antiguas.
bool cbcDecryptLegacy(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!openAesKey(key, BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), hAlg, hKey)) return false;

    DWORD plainLen = 0;
    std::vector<uint8_t> ivCopy = iv;
    BCryptDecrypt(hKey, const_cast<PUCHAR>(cipher.data()), static_cast<ULONG>(cipher.size()), nullptr,
                  ivCopy.data(), 16, nullptr, 0, &plainLen, BCRYPT_BLOCK_PADDING);

    plain.assign(plainLen, 0);
    ivCopy = iv;
    const NTSTATUS st = BCryptDecrypt(hKey, const_cast<PUCHAR>(cipher.data()), static_cast<ULONG>(cipher.size()), nullptr,
                                      ivCopy.data(), 16, plain.data(), plainLen, &plainLen, BCRYPT_BLOCK_PADDING);
    closeAes(hAlg, hKey);
    if (!NT_SUCCESS(st)) return false;
    plain.resize(plainLen);
    return true;
}

} // namespace

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

    // 1. Abrir con acceso exclusivo de lectura (nadie puede modificarlo ni borrarlo mientras se aísla)
    HANDLE hSrc = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hSrc == INVALID_HANDLE_VALUE) return std::nullopt;

    LARGE_INTEGER li{};
    if (!GetFileSizeEx(hSrc, &li) || li.QuadPart < 0 || static_cast<uint64_t>(li.QuadPart) > kMaxQuarantineBytes) {
        CloseHandle(hSrc);
        return std::nullopt;
    }
    const size_t fileSize = static_cast<size_t>(li.QuadPart);
    std::vector<uint8_t> plainData(fileSize);
    size_t done = 0;
    while (done < fileSize) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(fileSize - done, 16u * 1024u * 1024u));
        DWORD got = 0;
        if (!ReadFile(hSrc, plainData.data() + done, chunk, &got, nullptr) || got == 0) {
            CloseHandle(hSrc);
            return std::nullopt;
        }
        done += got;
    }
    CloseHandle(hSrc);

    // Si el llamador indicó el hash analizado, el contenido actual debe coincidir: evita aislar (y destruir)
    // un archivo distinto al que se analizó (carrera entre el análisis y el aislamiento).
    const std::string actualSha = plainData.empty() ? std::string() : CryptoUtils::computeSha256FromBuffer(plainData.data(), plainData.size());
    for (auto& c : sha256) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!sha256.empty() && !actualSha.empty() && actualSha != sha256) return std::nullopt;
    if (sha256.empty()) sha256 = actualSha;

    // 2. Cifrado autenticado AES-256-GCM (CNG); la cabecera de 12 bytes se autentica como AAD
    std::vector<uint8_t> header(12);
    std::memcpy(header.data(), VAULT_MAGIC_V2, 4);
    const uint64_t origSize64 = static_cast<uint64_t>(fileSize);
    std::memcpy(header.data() + 4, &origSize64, 8);

    std::vector<uint8_t> nonce, tag, cipherData;
    if (!gcmEncrypt(m_aesKey, header, nonce, plainData, cipherData, tag)) return std::nullopt;

    // 3. Escribir archivo cifrado en la bóveda (.qbin)
    std::string qid = generateQID(filePath);
    std::string encFileName = qid + ".qbin";
    std::filesystem::path encFilePath = m_filesDir / encFileName;

    std::ofstream outEnc(encFilePath, std::ios::binary | std::ios::trunc);
    if (!outEnc.is_open()) return std::nullopt;

    // Cabecera v2: Magic (4B) + OriginalSize (8B) + Nonce (12B) + Tag (16B) + Cifrado
    outEnc.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));
    outEnc.write(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
    outEnc.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
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

    // 2. Leer el archivo cifrado de la bóveda
    std::filesystem::path encPath = m_filesDir / encFileName;
    std::ifstream inEnc(encPath, std::ios::binary);
    if (!inEnc.is_open()) return false;
    std::vector<uint8_t> blob((std::istreambuf_iterator<char>(inEnc)), std::istreambuf_iterator<char>());
    inEnc.close();

    // 3. Descifrar según el formato: v2 = AES-256-GCM autenticado; v1 (heredado) = AES-256-CBC
    std::vector<uint8_t> plainData;
    uint64_t origSize = 0;
    if (blob.size() >= kGcmHeaderSize && std::memcmp(blob.data(), VAULT_MAGIC_V2, 4) == 0) {
        std::memcpy(&origSize, blob.data() + 4, 8);
        if (!gcmDecrypt(m_aesKey, blob, plainData)) return false; // etiqueta inválida: archivo manipulado o clave distinta
    } else if (blob.size() >= 28 && std::memcmp(blob.data(), VAULT_MAGIC, 4) == 0) {
        std::memcpy(&origSize, blob.data() + 4, 8);
        const std::vector<uint8_t> iv(blob.begin() + 12, blob.begin() + 28);
        const std::vector<uint8_t> cipher(blob.begin() + 28, blob.end());
        if (cipher.empty() || cipher.size() % 16 != 0 || !cbcDecryptLegacy(m_aesKey, iv, cipher, plainData)) return false;
    } else {
        return false;
    }

    // Ajustar al tamaño original registrado
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

