/**
 * @file test_quarantine.cpp
 * @brief Pruebas unitarias para la bóveda de cuarentena cifrada con AES-256 (QuarantineVault).
 */

#include "openguard/quarantine.h"
#include "openguard/crypto_utils.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

class QuarantineTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_testDir = std::filesystem::temp_directory_path() / "openguard_vault_test";
        std::filesystem::create_directories(m_testDir);
        m_vaultDir = m_testDir / "vault";
        m_vault = std::make_unique<openguard::QuarantineVault>(m_vaultDir);
    }

    void TearDown() override {
        m_vault.reset();
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::filesystem::path m_testDir;
    std::filesystem::path m_vaultDir;
    std::unique_ptr<openguard::QuarantineVault> m_vault;
};

// Probar aislamiento, cifrado y posterior restauración exacta de un archivo
TEST_F(QuarantineTest, EncryptsAndRestoresFileAccurately) {
    auto infectedFile = m_testDir / "payload_sospechoso.bin";
    const std::string originalData = "DATOS_CRITICOS_DE_PRUEBA_AES_256_OPENGUARD_DEFENSA";

    std::ofstream ofs(infectedFile, std::ios::binary);
    ofs << originalData;
    ofs.close();

    std::string originalSha256 = openguard::CryptoUtils::computeSha256(infectedFile);

    // 1. Aislar en cuarentena
    auto itemOpt = m_vault->quarantineFile(
        infectedFile,
        "Trojan.Simulado.Test",
        "high",
        originalSha256
    );

    ASSERT_TRUE(itemOpt.has_value());
    EXPECT_FALSE(std::filesystem::exists(infectedFile)); // Debe haber sido destruido de su origen
    EXPECT_EQ(m_vault->getItemCount(), 1);

    // 2. Restaurar a una ruta destino alternativa
    auto restoredFile = m_testDir / "restaurado.bin";
    bool restored = m_vault->restoreFile(itemOpt->qid, restoredFile);

    EXPECT_TRUE(restored);
    ASSERT_TRUE(std::filesystem::exists(restoredFile));
    EXPECT_EQ(m_vault->getItemCount(), 0);

    // Verificar que los datos descifrados coincidan exactamente bit a bit
    std::string restoredSha256 = openguard::CryptoUtils::computeSha256(restoredFile);
    EXPECT_EQ(restoredSha256, originalSha256);
}

// Probar eliminación permanente y purga segura de la cuarentena
TEST_F(QuarantineTest, PermanentlyDeletesItem) {
    auto badFile = m_testDir / "eliminar_permanente.bin";
    std::ofstream ofs(badFile);
    ofs << "CONTENIDO_A_PURGAR";
    ofs.close();

    auto itemOpt = m_vault->quarantineFile(badFile, "Malware.Purgable", "medium");
    ASSERT_TRUE(itemOpt.has_value());
    EXPECT_EQ(m_vault->getItemCount(), 1);

    bool deleted = m_vault->deletePermanently(itemOpt->qid);
    EXPECT_TRUE(deleted);
    EXPECT_EQ(m_vault->getItemCount(), 0);
}

