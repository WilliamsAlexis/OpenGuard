/**
 * @file secrets.cpp
 * @brief Implementación del almacén de secretos con DPAPI.
 */

#include "openguard/secrets.h"
#include "openguard/paths.h"

#include <windows.h>
#include <dpapi.h>
#include <wincrypt.h>

#include <cctype>
#include <fstream>
#include <iterator>
#include <vector>

#pragma comment(lib, "crypt32.lib")

namespace openguard {

SecretStore::SecretStore(std::filesystem::path directory) : m_dir(std::move(directory)) {
    if (m_dir.empty()) m_dir = paths::dataDir() / "secrets";
    std::error_code ec;
    std::filesystem::create_directories(m_dir, ec);
}

std::filesystem::path SecretStore::fileFor(const std::string& name) const {
    // Solo letras, números, guion y guion bajo: evita que un nombre apunte fuera de la carpeta
    std::string safe;
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-') safe.push_back(c);
        else return {};
    }
    if (safe.empty() || safe.size() > 64) return {};
    return m_dir / (safe + ".bin");
}

bool SecretStore::set(const std::string& name, const std::string& value) {
    const auto file = fileFor(name);
    if (file.empty() || value.empty() || value.size() > 4096) return false;

    DATA_BLOB in{};
    in.cbData = static_cast<DWORD>(value.size());
    in.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(value.data()));
    DATA_BLOB out{};
    // Entropía adicional: el blob solo se descifra con este contexto, no con cualquier uso de DPAPI
    static const char kEntropy[] = "OpenGuard.SecretStore.v1";
    DATA_BLOB entropy{};
    entropy.cbData = sizeof(kEntropy) - 1;
    entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy));

    if (!CryptProtectData(&in, L"OpenGuard secret", &entropy, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &out)) return false;

    std::ofstream f(file, std::ios::binary | std::ios::trunc);
    bool ok = f.is_open();
    if (ok) {
        f.write(reinterpret_cast<const char*>(out.pbData), static_cast<std::streamsize>(out.cbData));
        ok = f.good();
    }
    LocalFree(out.pbData);
    return ok;
}

std::optional<std::string> SecretStore::get(const std::string& name) const {
    const auto file = fileFor(name);
    if (file.empty()) return std::nullopt;

    std::ifstream f(file, std::ios::binary);
    if (!f.is_open()) return std::nullopt;
    std::vector<BYTE> blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (blob.empty() || blob.size() > 16 * 1024) return std::nullopt;

    DATA_BLOB in{};
    in.cbData = static_cast<DWORD>(blob.size());
    in.pbData = blob.data();
    static const char kEntropy[] = "OpenGuard.SecretStore.v1";
    DATA_BLOB entropy{};
    entropy.cbData = sizeof(kEntropy) - 1;
    entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy));
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, 0, &out)) return std::nullopt;

    std::string value(reinterpret_cast<char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return value;
}

bool SecretStore::remove(const std::string& name) {
    const auto file = fileFor(name);
    if (file.empty()) return false;
    std::error_code ec;
    std::filesystem::remove(file, ec);
    return !std::filesystem::exists(file, ec);
}

bool SecretStore::has(const std::string& name) const {
    const auto file = fileFor(name);
    std::error_code ec;
    return !file.empty() && std::filesystem::exists(file, ec);
}

} // namespace openguard
