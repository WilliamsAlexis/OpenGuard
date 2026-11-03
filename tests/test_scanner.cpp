/**
 * @file test_scanner.cpp
 * @brief Pruebas unitarias para el motor de escaneo y heurísticas de archivos (FileScanner).
 */

#include "openguard/scanner.h"
#include "openguard/signatures.h"
#include "openguard/crypto_utils.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

class ScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_testDir = std::filesystem::temp_directory_path() / "openguard_scan_test";
        std::filesystem::create_directories(m_testDir);

        m_dbPath = m_testDir / "scanner_test.db";
        m_sigDb = std::make_shared<openguard::SignatureDB>(m_dbPath);
        m_scanner = std::make_unique<openguard::FileScanner>(m_sigDb);
    }

    void TearDown() override {
        m_scanner.reset();
        m_sigDb.reset();
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::filesystem::path m_testDir;
    std::filesystem::path m_dbPath;
    std::shared_ptr<openguard::SignatureDB> m_sigDb;
    std::unique_ptr<openguard::FileScanner> m_scanner;
};

// Probar escaneo de un archivo limpio
TEST_F(ScannerTest, CleanFileIsClean) {
    auto cleanFile = m_testDir / "benigno.txt";
    std::ofstream ofs(cleanFile);
    ofs << "Contenido de texto legítimo y sin firmas sospechosas.";
    ofs.close();

    auto result = m_scanner->scanFile(cleanFile);

    EXPECT_EQ(result.riskLevel, openguard::RiskLevel::Clean);
    EXPECT_FALSE(result.isThreat());
    EXPECT_EQ(result.riskScore, 0);
    EXPECT_FALSE(result.sha256.empty());
}

// Probar detección de archivo por firma registrada
TEST_F(ScannerTest, DetectsKnownMalwareSignature) {
    auto infectedFile = m_testDir / "simulado_malware.bin";
    const std::string payload = "PAYLOAD_DE_PRUEBA_OPENGUARD_DEFENSA";
    std::ofstream ofs(infectedFile, std::ios::binary);
    ofs << payload;
    ofs.close();

    std::string expectedSha256 = openguard::CryptoUtils::computeSha256(infectedFile);

    // Registrar la firma en la base de datos
    openguard::SignatureRecord rec;
    rec.sha256 = expectedSha256;
    rec.malwareName = "Test.Malware.Simulado";
    rec.severity = "high";
    m_sigDb->addSignature(rec);

    // Escanear el archivo generado
    auto result = m_scanner->scanFile(infectedFile);

    EXPECT_TRUE(result.isThreat());
    EXPECT_EQ(result.riskLevel, openguard::RiskLevel::High);
    EXPECT_GE(result.riskScore, 75);
    ASSERT_FALSE(result.threats.empty());
    EXPECT_EQ(result.threats[0].name, "Test.Malware.Simulado");
}

// Probar detección heurística de doble extensión engañosa
TEST_F(ScannerTest, DetectsSuspiciousDoubleExtension) {
    auto deceptiveFile = m_testDir / "factura_pago.pdf.exe";
    std::ofstream ofs(deceptiveFile, std::ios::binary);
    ofs << "MZ_SIMULADO";
    ofs.close();

    auto result = m_scanner->scanFile(deceptiveFile);

    EXPECT_TRUE(result.isThreat());
    bool foundDoubleExt = false;
    for (const auto& threat : result.threats) {
        if (threat.name == "Heuristic.DoubleExtension") {
            foundDoubleExt = true;
            break;
        }
    }
    EXPECT_TRUE(foundDoubleExt);
}

