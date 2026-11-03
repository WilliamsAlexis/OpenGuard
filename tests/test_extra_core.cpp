/**
 * @file test_extra_core.cpp
 * @brief Pruebas adicionales: EICAR real, importación JSON, escaneo recursivo y cuarentena.
 */

#include "openguard/crypto_utils.h"
#include "openguard/quarantine.h"
#include "openguard/scanner.h"
#include "openguard/signatures.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <memory>

namespace fs = std::filesystem;

static const char kEicar[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

class CoreFixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = fs::temp_directory_path() / ("openguard_extra_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
                                             "_" + ::testing::UnitTest::GetInstance()->current_test_info()->name());
        std::error_code ec;
        fs::remove_all(m_dir, ec);
        fs::create_directories(m_dir);
        m_db = std::make_shared<openguard::SignatureDB>(m_dir / "sigs.db");
    }

    void TearDown() override {
        m_db.reset();
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }

    static void writeFile(const fs::path& p, const std::string& content) {
        std::ofstream ofs(p, std::ios::binary);
        ofs << content;
    }

    fs::path m_dir;
    std::shared_ptr<openguard::SignatureDB> m_db;
};

// ----------------------------------------------------------------------------- firmas

TEST_F(CoreFixture, EicarSignatureMatchesRealEicarFile) {
    m_db->seedEicar();

    const std::string eicar(kEicar);
    ASSERT_EQ(eicar.size(), 68u);

    const auto sha256 = openguard::CryptoUtils::computeSha256FromBuffer(eicar.data(), eicar.size());
    auto match = m_db->lookup(sha256);
    ASSERT_TRUE(match.has_value());
    EXPECT_EQ(match->malwareName, "EICAR-Standard-AV-Test-File");
    EXPECT_EQ(match->sha1.size(), 40u); // SHA-1 válido (el original tenía 39 caracteres)
}

TEST_F(CoreFixture, ImportFromJsonInsertsValidAndSkipsInvalid) {
    const auto jsonPath = m_dir / "sigs.json";
    writeFile(jsonPath, R"({
      "signatures": [
        {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
         "malware_name": "Json.Valida.A", "severity": "critical", "threat_type": "trojan"},
        {"sha256": "ZZZZ", "malware_name": "Json.HashInvalido"},
        {"malware_name": "Json.SinHash"},
        {"md5": "44d88612fea8a8f36de82e1278abb02f", "malware_name": "Json.Valida.Md5"},
        "no-es-un-objeto"
      ]
    })");

    size_t inserted = 0, skipped = 0;
    ASSERT_TRUE(m_db->importFromJson(jsonPath, inserted, skipped));
    EXPECT_EQ(inserted, 2u);
    EXPECT_EQ(skipped, 3u);

    auto bySha = m_db->lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ASSERT_TRUE(bySha.has_value());
    EXPECT_EQ(bySha->malwareName, "Json.Valida.A");
    EXPECT_EQ(bySha->severity, "critical");

    // Segunda importación: es idempotente
    ASSERT_TRUE(m_db->importFromJson(jsonPath, inserted, skipped));
    EXPECT_EQ(inserted, 0u);
}

TEST_F(CoreFixture, ImportFromMissingOrCorruptJsonFails) {
    size_t inserted = 0, skipped = 0;
    EXPECT_FALSE(m_db->importFromJson(m_dir / "no_existe.json", inserted, skipped));

    const auto badPath = m_dir / "corrupto.json";
    writeFile(badPath, "{ esto no es json");
    EXPECT_FALSE(m_db->importFromJson(badPath, inserted, skipped));
}

TEST_F(CoreFixture, ShippedSignatureIndexIsImportable) {
    const auto shipped = fs::path(OPENGUARD_SOURCE_DIR) / "signatures" / "hashes_index.json";
    ASSERT_TRUE(fs::exists(shipped));

    size_t inserted = 0, skipped = 0;
    ASSERT_TRUE(m_db->importFromJson(shipped, inserted, skipped));
    EXPECT_GT(inserted, 0u);
    EXPECT_EQ(skipped, 0u) << "El indice distribuido contiene registros malformados";
}

// ----------------------------------------------------------------------------- escáner

TEST_F(CoreFixture, ScannerDetectsEicarTestFile) {
    m_db->seedEicar();
    openguard::FileScanner scanner(m_db);

    const auto eicarFile = m_dir / "eicar.com";
    writeFile(eicarFile, kEicar);

    auto result = scanner.scanFile(eicarFile);
    EXPECT_TRUE(result.isThreat());
    ASSERT_FALSE(result.threats.empty());
    EXPECT_EQ(result.threats[0].name, "EICAR-Standard-AV-Test-File");
    EXPECT_EQ(result.threats[0].method, "hash_signature");
}

TEST_F(CoreFixture, HashMatchWithLowSeverityIsStillThreat) {
    const auto file = m_dir / "low.bin";
    writeFile(file, "contenido-baja-severidad");

    openguard::SignatureRecord rec;
    rec.sha256 = openguard::CryptoUtils::computeSha256(file);
    rec.malwareName = "Test.LowSeverity";
    rec.severity = "low";
    ASSERT_TRUE(m_db->addSignature(rec));

    openguard::FileScanner scanner(m_db);
    EXPECT_TRUE(scanner.scanFile(file).isThreat());
}

TEST_F(CoreFixture, ScanPathAggregatesSessionStats) {
    const auto root = m_dir / "carpeta";
    const auto sub = root / "interna";
    fs::create_directories(sub);
    for (int i = 0; i < 5; ++i) {
        writeFile(sub / ("limpio_" + std::to_string(i) + ".txt"), "texto inofensivo numero " + std::to_string(i));
    }
    writeFile(sub / "informe.pdf.exe", "MZ");

    openguard::FileScanner scanner(m_db);
    auto session = scanner.scanPath(root);
    EXPECT_EQ(session.filesScanned, 6u);
    EXPECT_EQ(session.threatsFound, 1u);
    EXPECT_EQ(session.results.size(), 1u); // Los archivos limpios no se acumulan en memoria
}

TEST_F(CoreFixture, ScanPathHandlesMoreFilesThanOneBatch) {
    const auto root = m_dir / "muchos";
    fs::create_directories(root);
    for (int i = 0; i < 700; ++i) { // > 512: fuerza más de un lote interno
        writeFile(root / ("f" + std::to_string(i) + ".txt"), "contenido " + std::to_string(i));
    }

    openguard::FileScanner scanner(m_db);
    auto session = scanner.scanPath(root);
    EXPECT_EQ(session.filesScanned, 700u);
    EXPECT_EQ(session.threatsFound, 0u);
}

TEST_F(CoreFixture, ExcludedPathsAreSkipped) {
    const auto excluded = m_dir / "excluida";
    fs::create_directories(excluded);
    writeFile(excluded / "factura.pdf.exe", "MZ");

    openguard::ScannerConfig cfg;
    cfg.excludedPaths.push_back(excluded);
    openguard::FileScanner scanner(m_db, cfg);

    auto session = scanner.scanPath(m_dir);
    EXPECT_EQ(session.threatsFound, 0u);
}

TEST_F(CoreFixture, FixedDrivesIncludeSystemDrive) {
    const auto drives = openguard::FileScanner::getFixedDrives();
    EXPECT_FALSE(drives.empty());
}

// ----------------------------------------------------------------------------- cuarentena

TEST_F(CoreFixture, QuarantineKeyPersistsAcrossVaultInstances) {
    const auto vaultDir = m_dir / "vault";
    const auto file = m_dir / "persistente.bin";
    writeFile(file, "CONTENIDO_PERSISTENTE_123");
    const std::string sha = openguard::CryptoUtils::computeSha256(file);

    std::string qid;
    {
        openguard::QuarantineVault vault(vaultDir);
        auto item = vault.quarantineFile(file, "Test.Persist", "high", sha);
        ASSERT_TRUE(item.has_value());
        qid = item->qid;
    }

    openguard::QuarantineVault reopened(vaultDir);
    EXPECT_EQ(reopened.getItemCount(), 1u);

    const auto restored = m_dir / "restaurado_persistente.bin";
    ASSERT_TRUE(reopened.restoreFile(qid, restored));
    EXPECT_EQ(openguard::CryptoUtils::computeSha256(restored), sha);
}

TEST_F(CoreFixture, QuarantineRestoreRefusesToOverwrite) {
    openguard::QuarantineVault vault(m_dir / "vault");
    const auto file = m_dir / "origen.bin";
    writeFile(file, "ORIGINAL");
    auto item = vault.quarantineFile(file, "Test.NoOverwrite");
    ASSERT_TRUE(item.has_value());

    const auto occupied = m_dir / "ocupado.bin";
    writeFile(occupied, "NO_TOCAR");

    EXPECT_FALSE(vault.restoreFile(item->qid, occupied));
    EXPECT_EQ(vault.getItemCount(), 1u); // Sigue en cuarentena
}

TEST_F(CoreFixture, QuarantineRejectsTamperedVaultFile) {
    const auto vaultDir = m_dir / "vault";
    openguard::QuarantineVault vault(vaultDir);

    const auto file = m_dir / "manipulado.bin";
    writeFile(file, "DATOS_A_MANIPULAR_DATOS_A_MANIPULAR");
    auto item = vault.quarantineFile(file, "Test.Tamper");
    ASSERT_TRUE(item.has_value());

    // Corromper un byte del bloque cifrado (tras la cabecera de 28 bytes)
    const auto encPath = vaultDir / "files" / item->encryptedFileName;
    {
        std::fstream f(encPath, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(f.is_open());
        f.seekp(30);
        f.put('\x7F');
    }

    const auto target = m_dir / "no_debe_existir.bin";
    EXPECT_FALSE(vault.restoreFile(item->qid, target));
    EXPECT_FALSE(fs::exists(target));
}

TEST_F(CoreFixture, QuarantinePreservesUnicodeOriginalPath) {
    openguard::QuarantineVault vault(m_dir / "vault");

    const auto dir = m_dir / fs::path(L"carpeta_ñandú_日本");
    fs::create_directories(dir);
    const auto file = dir / fs::path(L"archivo_é.bin");
    writeFile(file, "UNICODE");

    auto item = vault.quarantineFile(file, "Test.Unicode");
    ASSERT_TRUE(item.has_value());

    auto items = vault.listItems();
    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items[0].originalPath, file);
}
