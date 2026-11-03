/**
 * @file test_feeds.cpp
 * @brief Pruebas de la verificación de firmas de actualización, el almacén de secretos y los importadores de fuentes.
 */

#include "openguard/crypto_utils.h"
#include "openguard/feeds.h"
#include "openguard/secrets.h"
#include "openguard/settings.h"
#include "openguard/update_verify.h"
#include "openguard/yara_lite.h"

#include <gtest/gtest.h>

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

namespace fs = std::filesystem;

namespace {

/// Lee un archivo y normaliza CRLF -> LF (las firmas se calculan sobre LF, como los sirve GitHub).
std::string readLf(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\r' && i + 1 < s.size() && s[i + 1] == '\n') continue;
        out.push_back(s[i]);
    }
    return out;
}

/// Par de claves ECDSA P-256 generado con CNG solo para las pruebas.
struct TestKey {
    BCRYPT_ALG_HANDLE alg{nullptr};
    BCRYPT_KEY_HANDLE key{nullptr};
    openguard::EcPublicKey pub;

    TestKey() {
        EXPECT_TRUE(NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0)));
        EXPECT_TRUE(NT_SUCCESS(BCryptGenerateKeyPair(alg, &key, 256, 0)));
        EXPECT_TRUE(NT_SUCCESS(BCryptFinalizeKeyPair(key, 0)));

        ULONG len = 0;
        BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &len, 0);
        std::vector<uint8_t> blob(len);
        EXPECT_TRUE(NT_SUCCESS(BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), len, &len, 0)));
        std::memcpy(pub.x.data(), blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), 32);
        std::memcpy(pub.y.data(), blob.data() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, 32);
    }
    ~TestKey() {
        if (key) BCryptDestroyKey(key);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    }

    std::vector<uint8_t> sign(const std::string& data) const {
        std::vector<uint8_t> digest(32);
        BCRYPT_ALG_HANDLE sha = nullptr;
        BCryptOpenAlgorithmProvider(&sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(sha, &h, nullptr, 0, nullptr, 0, 0);
        BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())), static_cast<ULONG>(data.size()), 0);
        BCryptFinishHash(h, digest.data(), 32, 0);
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(sha, 0);

        std::vector<uint8_t> sig(64);
        ULONG written = 0;
        EXPECT_TRUE(NT_SUCCESS(BCryptSignHash(key, nullptr, digest.data(), 32, sig.data(), 64, &written, 0)));
        return sig;
    }
};

} // namespace

// ----------------------------------------------------------------------------- base64 y ECDSA

TEST(UpdateVerifyTest, Base64RoundTripAndValidation) {
    for (size_t n : {0u, 1u, 2u, 3u, 4u, 63u, 64u, 65u}) {
        std::vector<uint8_t> data(n);
        for (size_t i = 0; i < n; ++i) data[i] = static_cast<uint8_t>(i * 37 + 11);
        EXPECT_EQ(openguard::base64Decode(openguard::base64Encode(data)), data) << "longitud " << n;
    }
    EXPECT_EQ(openguard::base64Encode({'M', 'a', 'n'}), "TWFu");
    EXPECT_EQ(openguard::base64Decode("TWFu\r\n"), (std::vector<uint8_t>{'M', 'a', 'n'})); // tolera saltos de linea
    EXPECT_TRUE(openguard::base64Decode("@@@@").empty());
    EXPECT_TRUE(openguard::base64Decode("TW=u").empty()); // relleno en mitad del texto
}

TEST(UpdateVerifyTest, EcdsaAcceptsValidAndRejectsTampering) {
    TestKey key;
    const std::string data = "contenido firmado de prueba";
    auto sig = key.sign(data);
    ASSERT_EQ(sig.size(), 64u);

    EXPECT_TRUE(openguard::verifyEcdsaP256(data.data(), data.size(), sig, key.pub));

    const std::string tampered = data + "!";
    EXPECT_FALSE(openguard::verifyEcdsaP256(tampered.data(), tampered.size(), sig, key.pub));

    auto badSig = sig;
    badSig[10] ^= 0x01;
    EXPECT_FALSE(openguard::verifyEcdsaP256(data.data(), data.size(), badSig, key.pub));

    TestKey other; // otra clave: la firma no es suya
    EXPECT_FALSE(openguard::verifyEcdsaP256(data.data(), data.size(), sig, other.pub));

    EXPECT_FALSE(openguard::verifyEcdsaP256(data.data(), data.size(), std::vector<uint8_t>(63), key.pub));
    EXPECT_FALSE(openguard::verifyEcdsaP256(data.data(), data.size(), {}, key.pub));
}

TEST(UpdateVerifyTest, ShippedSignedFilesVerifyWithOfficialKey) {
    // Si se edita el indice o una regla sin volver a firmar (scripts\sign_release_files.ps1), esta prueba falla.
    const fs::path sigDir = fs::path(OPENGUARD_SOURCE_DIR) / "signatures";

    for (const char* name : {"hashes_index.json", "rules_manifest.json"}) {
        const std::string content = readLf(sigDir / name);
        const std::string sig = readLf(sigDir / (std::string(name) + ".sig"));
        ASSERT_FALSE(content.empty()) << name;
        EXPECT_TRUE(openguard::verifyOfficialSignature(content, sig)) << "Firma invalida: " << name << " (ejecute scripts\\sign_release_files.ps1)";
        EXPECT_FALSE(openguard::verifyOfficialSignature(content + " ", sig)) << name;
    }
}

TEST(UpdateVerifyTest, ManifestMatchesShippedRuleFiles) {
    const fs::path sigDir = fs::path(OPENGUARD_SOURCE_DIR) / "signatures";
    const std::string manifest = readLf(sigDir / "rules_manifest.json");

    size_t checked = 0;
    for (const auto& entry : fs::directory_iterator(sigDir / "yara_rules")) {
        if (entry.path().extension() != ".yar") continue;
        const std::string content = readLf(entry.path());
        const std::string hash = openguard::CryptoUtils::computeSha256FromBuffer(content.data(), content.size());
        EXPECT_NE(manifest.find(entry.path().filename().string()), std::string::npos) << entry.path();
        EXPECT_NE(manifest.find(hash), std::string::npos) << "El hash de " << entry.path().filename() << " no coincide con el manifiesto firmado";
        ++checked;
    }
    EXPECT_GE(checked, 6u);
}

// ----------------------------------------------------------------------------- secretos

class SecretFixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = fs::temp_directory_path() / "openguard_secret_test";
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }
    fs::path m_dir;
};

TEST_F(SecretFixture, StoresEncryptedAndRoundTrips) {
    openguard::SecretStore store(m_dir);
    const std::string key = "abc123-clave-secreta-XYZ";
    ASSERT_TRUE(store.set("abusech_auth_key", key));
    EXPECT_TRUE(store.has("abusech_auth_key"));

    auto got = store.get("abusech_auth_key");
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, key);

    // En disco no debe aparecer en texto plano
    std::ifstream f(m_dir / "abusech_auth_key.bin", std::ios::binary);
    const std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_FALSE(raw.empty());
    EXPECT_EQ(raw.find(key), std::string::npos);

    // Reemplazo y eliminacion
    ASSERT_TRUE(store.set("abusech_auth_key", "otra"));
    EXPECT_EQ(*store.get("abusech_auth_key"), "otra");
    EXPECT_TRUE(store.remove("abusech_auth_key"));
    EXPECT_FALSE(store.has("abusech_auth_key"));
    EXPECT_FALSE(store.get("abusech_auth_key").has_value());
}

TEST_F(SecretFixture, RejectsUnsafeNamesAndEmptyValues) {
    openguard::SecretStore store(m_dir);
    EXPECT_FALSE(store.set("../escape", "x"));
    EXPECT_FALSE(store.set("a/b", "x"));
    EXPECT_FALSE(store.set("a b", "x"));
    EXPECT_FALSE(store.set("", "x"));
    EXPECT_FALSE(store.set("valido", ""));
    EXPECT_FALSE(store.get("../escape").has_value());
    EXPECT_FALSE(store.has("no_existe"));
}

TEST_F(SecretFixture, CorruptedBlobIsRejected) {
    openguard::SecretStore store(m_dir);
    ASSERT_TRUE(store.set("k", "valor"));
    {
        std::ofstream f(m_dir / "k.bin", std::ios::binary | std::ios::trunc);
        f << "esto no es un blob DPAPI";
    }
    EXPECT_FALSE(store.get("k").has_value());
}

// ----------------------------------------------------------------------------- importadores

TEST(FeedParsersTest, ParsesMalwareBazaarCsv) {
    const std::string csv =
        "################################################################\r\n"
        "# MalwareBazaar recent additions\r\n"
        "# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh\r\n"
        "################################################################\r\n"
        "\"2026-01-01 10:00:00\", \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", "
        "\"11111111111111111111111111111111\", \"2222222222222222222222222222222222222222\", \"rep\", \"a.exe\", \"exe\", \"application/x-dosexec\", "
        "\"AgentTesla\", \"n/a\", \"50\", \"\", \"\", \"\"\r\n"
        "\"2026-01-01 10:01:00\", \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\", \"\", \"\", \"rep\", \"b.dll\", \"dll\", \"x\", \"n/a\", \"\", \"\", \"\", \"\", \"\"\r\n"
        "\"2026-01-01 10:02:00\", \"hash-invalido\", \"\", \"\", \"rep\", \"c\", \"c\", \"c\", \"Algo\"\r\n"
        "linea sin comillas ni campos\r\n";

    std::vector<openguard::SignatureRecord> out;
    auto st = openguard::parseMalwareBazaarCsv(csv, out);
    EXPECT_EQ(st.parsed, 2u);
    EXPECT_EQ(st.skipped, 2u);
    ASSERT_EQ(out.size(), 2u);

    EXPECT_EQ(out[0].sha256, std::string(64, 'a'));
    EXPECT_EQ(out[0].md5, std::string(32, '1'));
    EXPECT_EQ(out[0].sha1, std::string(40, '2'));
    EXPECT_EQ(out[0].malwareName, "MalwareBazaar.AgentTesla");
    EXPECT_EQ(out[0].source, "malwarebazaar");

    EXPECT_EQ(out[1].sha256, std::string(64, 'b')); // se normaliza a minusculas
    EXPECT_EQ(out[1].malwareName, "MalwareBazaar.Unknown"); // "n/a" -> Unknown
}

TEST(FeedParsersTest, MalwareBazaarNamesAreSanitized) {
    const std::string longName(200, 'X');
    const std::string csv = "\"t\", \"" + std::string(64, 'c') + "\", \"\", \"\", \"r\", \"f\", \"t\", \"m\", \"Mal\x01ware" + longName + "\"\r\n";
    std::vector<openguard::SignatureRecord> out;
    openguard::parseMalwareBazaarCsv(csv, out);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_LE(out[0].malwareName.size(), std::string("MalwareBazaar.").size() + 80);
    EXPECT_EQ(out[0].malwareName.find('\x01'), std::string::npos);
}

TEST(FeedParsersTest, ParsesClamAvHashDatabases) {
    const std::string db =
        "# comentario\n"
        "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n"
        "3395856ce81f2b7382dee72602f798b642f14140:68:Eicar-Sha1\n"
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Eicar-Sha256\n"
        "zzzz:10:Malo\n"
        "sin-separadores\n";

    std::vector<openguard::SignatureRecord> out;
    auto st = openguard::parseClamAvHashDb(db, out);
    EXPECT_EQ(st.parsed, 3u);
    EXPECT_EQ(st.skipped, 2u);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0].md5, "44d88612fea8a8f36de82e1278abb02f");
    EXPECT_EQ(out[0].malwareName, "ClamAV.Eicar-Test-Signature");
    EXPECT_FALSE(out[1].sha1.empty());
    EXPECT_FALSE(out[2].sha256.empty());
}

TEST(FeedParsersTest, ImportedRecordsAreDetectableAfterBulkImport) {
    const fs::path dir = fs::temp_directory_path() / "openguard_feed_import_test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    {
        openguard::SignatureDB db(dir / "s.db");
        std::vector<openguard::SignatureRecord> recs;
        openguard::parseClamAvHashDb("44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n", recs);
        size_t ins = 0, skp = 0;
        ASSERT_TRUE(db.bulkImport(recs, ins, skp));
        EXPECT_EQ(ins, 1u);
        auto hit = db.lookup("", "", "44d88612fea8a8f36de82e1278abb02f");
        ASSERT_TRUE(hit.has_value());
        EXPECT_EQ(hit->malwareName, "ClamAV.Eicar-Test-Signature");
    }
    fs::remove_all(dir, ec);
}

// ----------------------------------------------------------------------------- reglas y ajustes

TEST(YaraDirectoriesTest, OverrideDirectoryReplacesSameNamedFiles) {
    const fs::path root = fs::temp_directory_path() / "openguard_yara_override_test";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root / "base");
    fs::create_directories(root / "upd");

    auto rule = [](const std::string& name, const std::string& marker) {
        return "rule " + name + " {\n    strings:\n        $a = \"" + marker + "\"\n    condition:\n        $a\n}\n";
    };
    { std::ofstream(root / "base" / "comun.yar") << rule("Base_Comun", "MARCA_BASE"); }
    { std::ofstream(root / "base" / "solo_base.yar") << rule("Solo_Base", "MARCA_SOLO_BASE"); }
    { std::ofstream(root / "upd" / "COMUN.yar") << rule("Upd_Comun", "MARCA_UPD"); } // mismo nombre (otra capitalizacion)
    { std::ofstream(root / "upd" / "nueva.yar") << rule("Upd_Nueva", "MARCA_NUEVA"); }

    openguard::YaraLite y;
    EXPECT_EQ(y.loadDirectories(root / "base", root / "upd"), 3u); // Upd_Comun + Upd_Nueva + Solo_Base (Base_Comun descartada)

    auto scan = [&y](const std::string& s) { return y.scan(reinterpret_cast<const uint8_t*>(s.data()), s.size()); };
    EXPECT_EQ(scan("MARCA_BASE").size(), 0u);          // la versión de la instalación fue reemplazada
    EXPECT_EQ(scan("MARCA_UPD").size(), 1u);
    EXPECT_EQ(scan("MARCA_SOLO_BASE").size(), 1u);

    openguard::YaraLite onlyBase;
    EXPECT_EQ(onlyBase.loadDirectories(root / "base", root / "no_existe"), 2u);

    fs::remove_all(root, ec);
}

TEST(FeedSettingsTest, UpdateSettingsRoundTrip) {
    const fs::path dir = fs::temp_directory_path() / "openguard_feed_settings_test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);

    auto d = openguard::ProtectionSettings::load(dir / "c.ini");
    EXPECT_TRUE(d.autoUpdate);
    EXPECT_EQ(d.updateHours, 6);
    EXPECT_TRUE(d.feedRules);
    EXPECT_FALSE(d.feedBazaar);

    openguard::ProtectionSettings s;
    s.autoUpdate = false;
    s.updateHours = 24;
    s.feedRules = false;
    s.feedBazaar = true;
    ASSERT_TRUE(s.save(dir / "c.ini"));
    auto l = openguard::ProtectionSettings::load(dir / "c.ini");
    EXPECT_FALSE(l.autoUpdate);
    EXPECT_EQ(l.updateHours, 24);
    EXPECT_FALSE(l.feedRules);
    EXPECT_TRUE(l.feedBazaar);

    s.updateHours = 100000; // fuera de rango: se acota
    ASSERT_TRUE(s.save(dir / "c.ini"));
    EXPECT_EQ(openguard::ProtectionSettings::load(dir / "c.ini").updateHours, 168);

    fs::remove_all(dir, ec);
}
