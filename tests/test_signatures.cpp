/**
 * @file test_signatures.cpp
 * @brief Pruebas unitarias para el gestor de firmas criptográficas (SignatureDB).
 */

#include "openguard/signatures.h"
#include "openguard/crypto_utils.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

class SignatureDBTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Crear ruta temporal para la base de datos de pruebas
        m_testDir = std::filesystem::temp_directory_path() / "openguard_sig_test";
        std::filesystem::create_directories(m_testDir);
        m_testDbPath = m_testDir / "test_signatures.db";
        m_db = std::make_unique<openguard::SignatureDB>(m_testDbPath);
    }

    void TearDown() override {
        m_db.reset();
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::filesystem::path m_testDir;
    std::filesystem::path m_testDbPath;
    std::unique_ptr<openguard::SignatureDB> m_db;
};

// Verificar que la base de datos se inicializa y abre correctamente
TEST_F(SignatureDBTest, InitializesAndOpens) {
    ASSERT_TRUE(m_db->isOpen());
    ASSERT_TRUE(std::filesystem::exists(m_testDbPath));
}

// Probar inserción y búsqueda exitosa por SHA-256
TEST_F(SignatureDBTest, AddAndLookupBySha256) {
    openguard::SignatureRecord rec;
    rec.sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    rec.malwareName = "Trojan.Prueba.A";
    rec.severity = "high";
    rec.threatType = "trojan";

    bool added = m_db->addSignature(rec);
    EXPECT_TRUE(added);

    auto result = m_db->lookup(rec.sha256);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->malwareName, "Trojan.Prueba.A");
    EXPECT_EQ(result->severity, "high");
}

// Probar que un hash desconocido devuelva nullopt
TEST_F(SignatureDBTest, LookupUnknownReturnsNullopt) {
    auto result = m_db->lookup("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    EXPECT_FALSE(result.has_value());
}

// Probar inserción y búsqueda secundaria por SHA-1 y MD5
TEST_F(SignatureDBTest, LookupBySha1AndMd5) {
    openguard::SignatureRecord rec;
    rec.sha256 = "1111111111111111111111111111111111111111111111111111111111111111";
    rec.sha1   = "2222222222222222222222222222222222222222";
    rec.md5    = "33333333333333333333333333333333";
    rec.malwareName = "Ransom.MultiHash";
    rec.severity = "critical";

    m_db->addSignature(rec);

    // Búsqueda por SHA-1
    auto matchSha1 = m_db->lookup("", rec.sha1);
    ASSERT_TRUE(matchSha1.has_value());
    EXPECT_EQ(matchSha1->malwareName, "Ransom.MultiHash");

    // Búsqueda por MD5
    auto matchMd5 = m_db->lookup("", "", rec.md5);
    ASSERT_TRUE(matchMd5.has_value());
    EXPECT_EQ(matchMd5->malwareName, "Ransom.MultiHash");
}

// Verificar la función de sembrado de firmas EICAR
TEST_F(SignatureDBTest, SeedEicarInsertsExpectedSignatures) {
    m_db->seedEicar();

    auto matchEicar1 = m_db->lookup("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    ASSERT_TRUE(matchEicar1.has_value());
    EXPECT_EQ(matchEicar1->malwareName, "EICAR-Standard-AV-Test-File");

    auto matchEicar2 = m_db->lookup("131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267");
    ASSERT_TRUE(matchEicar2.has_value());
    EXPECT_EQ(matchEicar2->malwareName, "EICAR-Standard-AV-Test-File-LF");
}

// Probar importación masiva de firmas en transacción
TEST_F(SignatureDBTest, BulkImportInsertsRecordsAtomically) {
    std::vector<openguard::SignatureRecord> batch;
    for (int i = 0; i < 20; ++i) {
        openguard::SignatureRecord r;
        r.sha256 = std::string(62, '0') + (i < 10 ? "0" : "") + std::to_string(i);
        r.malwareName = "Batch.Threat." + std::to_string(i);
        batch.push_back(r);
    }

    size_t inserted = 0;
    size_t skipped = 0;
    bool success = m_db->bulkImport(batch, inserted, skipped);

    EXPECT_TRUE(success);
    EXPECT_EQ(inserted, 20);
    EXPECT_EQ(skipped, 0);

    auto stats = m_db->getStats();
    EXPECT_EQ(stats.totalSignatures, 20);
}

