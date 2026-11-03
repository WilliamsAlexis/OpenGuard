/**
 * @file test_hardening.cpp
 * @brief Pruebas de la Fase 0b: configuración compartida, historial, cuarentena autenticada y límites.
 */

#include "openguard/crypto_utils.h"
#include "openguard/history.h"
#include "openguard/quarantine.h"
#include "openguard/settings.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <cctype>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

class HardeningFixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = fs::temp_directory_path() / ("openguard_hard_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        std::error_code ec;
        fs::remove_all(m_dir, ec);
        fs::create_directories(m_dir);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }
    static void writeFile(const fs::path& p, const std::string& s) {
        std::ofstream o(p, std::ios::binary);
        o << s;
    }
    fs::path m_dir;
};

// ----------------------------------------------------------------------------- configuración

TEST_F(HardeningFixture, SettingsRoundTripAndDefaults) {
    const fs::path ini = m_dir / "config.ini";

    // Sin archivo: valores predeterminados
    auto defaults = openguard::ProtectionSettings::load(ini);
    EXPECT_TRUE(defaults.autoQuarantine);
    EXPECT_TRUE(defaults.decoys);
    EXPECT_TRUE(defaults.scanUsb);
    EXPECT_EQ(defaults.cpuPercent, 50);
    EXPECT_TRUE(defaults.exclusions.empty());

    openguard::ProtectionSettings s;
    s.autoQuarantine = false;
    s.scanUsb = false;
    s.cpuPercent = 25;
    s.exclusions = {fs::path(L"C:\\Datos\\Proyectos \u00F1and\u00FA"), fs::path(L"D:\\Juegos\\saves.dat")};
    ASSERT_TRUE(s.save(ini));

    auto loaded = openguard::ProtectionSettings::load(ini);
    EXPECT_FALSE(loaded.autoQuarantine);
    EXPECT_TRUE(loaded.decoys);
    EXPECT_FALSE(loaded.scanUsb);
    EXPECT_EQ(loaded.cpuPercent, 25);
    ASSERT_EQ(loaded.exclusions.size(), 2u);
    EXPECT_EQ(loaded.exclusions[0], s.exclusions[0]);

    // Guardar de nuevo con menos exclusiones no deja restos de la lista anterior
    s.exclusions.resize(1);
    ASSERT_TRUE(s.save(ini));
    EXPECT_EQ(openguard::ProtectionSettings::load(ini).exclusions.size(), 1u);
}

TEST_F(HardeningFixture, SettingsCpuLimitMapsToThreads) {
    openguard::ProtectionSettings s;
    s.cpuPercent = 10;
    EXPECT_GE(s.threadCount(), 1u);
    s.cpuPercent = 100;
    EXPECT_GE(s.threadCount(), 1u);

    s.cpuPercent = 25;
    const size_t low = s.threadCount();
    s.cpuPercent = 100;
    EXPECT_LE(low, s.threadCount());

    // Valores fuera de rango se acotan al guardar/cargar
    const fs::path ini = m_dir / "c.ini";
    s.cpuPercent = 9999;
    ASSERT_TRUE(s.save(ini));
    EXPECT_EQ(openguard::ProtectionSettings::load(ini).cpuPercent, 100);
}

TEST_F(HardeningFixture, ExclusionsMatchFoldersFilesAndAreCaseInsensitive) {
    openguard::ProtectionSettings s;
    s.exclusions = {fs::path(L"C:\\Juegos"), fs::path(L"D:\\notas.txt")};

    EXPECT_TRUE(s.isExcluded(L"C:\\Juegos\\Steam\\game.exe"));
    EXPECT_TRUE(s.isExcluded(L"c:\\juegos"));
    EXPECT_TRUE(s.isExcluded(L"C:\\JUEGOS\\a.bin"));
    EXPECT_TRUE(s.isExcluded(L"D:\\notas.txt"));
    EXPECT_FALSE(s.isExcluded(L"C:\\JuegosExtra\\a.bin")); // no es subcarpeta, solo comparte prefijo
    EXPECT_FALSE(s.isExcluded(L"C:\\Otra\\carpeta\\a.bin"));
    EXPECT_FALSE(s.isExcluded(L"D:\\notas.txt.exe"));
}

// ----------------------------------------------------------------------------- historial

TEST_F(HardeningFixture, HistoryStoresAndFiltersEvents) {
    openguard::ThreatHistory h(m_dir / "history.db");
    ASSERT_TRUE(h.isOpen());

    openguard::HistoryEvent e;
    e.kind = "detection";
    e.level = "ALERT";
    e.path = "C:\\Users\\Jos\u00E9\\descarga.exe";
    e.threat = "EICAR-Standard-AV-Test-File";
    e.action = "detectado";
    e.sha256 = "abc";
    ASSERT_TRUE(h.record(e));

    e.kind = "quarantine";
    e.level = "ACTION";
    e.action = "aislado";
    ASSERT_TRUE(h.record(e));

    EXPECT_EQ(h.count(), 2u);
    EXPECT_EQ(h.count("quarantine"), 1u);

    auto all = h.recent(10);
    ASSERT_EQ(all.size(), 2u);
    EXPECT_EQ(all[0].kind, "quarantine"); // más reciente primero
    EXPECT_FALSE(all[0].timestamp.empty());
    EXPECT_EQ(all[1].threat, "EICAR-Standard-AV-Test-File");

    auto onlyDet = h.recent(10, "detection");
    ASSERT_EQ(onlyDet.size(), 1u);
    EXPECT_EQ(onlyDet[0].path, e.path); // UTF-8 conservado

    EXPECT_EQ(h.recent(1).size(), 1u);
}

TEST_F(HardeningFixture, HistoryPersistsAndPurgesOldEvents) {
    const fs::path db = m_dir / "h.db";
    {
        openguard::ThreatHistory h(db);
        openguard::HistoryEvent old;
        old.timestamp = "2000-01-01 00:00:00";
        old.level = "INFO";
        old.kind = "system";
        ASSERT_TRUE(h.record(old));
        openguard::HistoryEvent recent;
        recent.level = "INFO";
        recent.kind = "system";
        ASSERT_TRUE(h.record(recent));
    }
    openguard::ThreatHistory reopened(db);
    EXPECT_EQ(reopened.count(), 2u);
    EXPECT_GE(reopened.purgeOlderThan(30), 1u);
    EXPECT_EQ(reopened.count(), 1u);
}

// ----------------------------------------------------------------------------- cuarentena autenticada

TEST_F(HardeningFixture, QuarantineUsesAuthenticatedFormat) {
    openguard::QuarantineVault vault(m_dir / "vault");
    const fs::path file = m_dir / "muestra.bin";
    writeFile(file, "CONTENIDO_DE_PRUEBA_PARA_GCM");

    auto item = vault.quarantineFile(file, "Test.Gcm");
    ASSERT_TRUE(item.has_value());

    std::ifstream enc(m_dir / "vault" / "files" / item->encryptedFileName, std::ios::binary);
    char magic[4]{};
    enc.read(magic, 4);
    EXPECT_EQ(std::string(magic, 4), "OGQ2");
}

TEST_F(HardeningFixture, TamperingAnyHeaderOrCipherByteIsDetected) {
    const std::string content = "DATOS_SENSIBLES_DATOS_SENSIBLES";
    // Se prueba un byte de cada zona: magic/tamaño (AAD), nonce, etiqueta y cuerpo cifrado
    for (int offset : {5, 14, 30, 41}) {
        const fs::path vaultDir = m_dir / ("v" + std::to_string(offset));
        openguard::QuarantineVault vault(vaultDir);
        const fs::path file = m_dir / ("f" + std::to_string(offset) + ".bin");
        writeFile(file, content);

        auto item = vault.quarantineFile(file, "Test.Tamper");
        ASSERT_TRUE(item.has_value());

        {
            std::fstream f(vaultDir / "files" / item->encryptedFileName, std::ios::in | std::ios::out | std::ios::binary);
            ASSERT_TRUE(f.is_open());
            f.seekg(offset);
            char c = 0;
            f.get(c);
            f.seekp(offset);
            f.put(static_cast<char>(c ^ 0x01));
        }
        const fs::path target = m_dir / ("out" + std::to_string(offset) + ".bin");
        EXPECT_FALSE(vault.restoreFile(item->qid, target)) << "Manipulacion no detectada en el byte " << offset;
        EXPECT_FALSE(fs::exists(target));
    }
}

TEST_F(HardeningFixture, QuarantineRefusesFileThatChangedSinceScan) {
    openguard::QuarantineVault vault(m_dir / "vault");
    const fs::path file = m_dir / "cambiado.bin";
    writeFile(file, "VERSION_ANALIZADA");
    const std::string scannedHash = openguard::CryptoUtils::computeSha256(file);

    writeFile(file, "OTRO_CONTENIDO_DISTINTO"); // el archivo cambió entre el análisis y el aislamiento

    EXPECT_FALSE(vault.quarantineFile(file, "Test.Toctou", "high", scannedHash).has_value());
    EXPECT_TRUE(fs::exists(file)); // no se destruye un archivo distinto del analizado
    EXPECT_EQ(vault.getItemCount(), 0u);
}

TEST_F(HardeningFixture, QuarantineAcceptsUppercaseHashAndEmptyFile) {
    openguard::QuarantineVault vault(m_dir / "vault");
    const fs::path file = m_dir / "mayus.bin";
    writeFile(file, "CONTENIDO");
    std::string hash = openguard::CryptoUtils::computeSha256(file);
    for (auto& c : hash) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    EXPECT_TRUE(vault.quarantineFile(file, "Test.Upper", "high", hash).has_value());

    const fs::path empty = m_dir / "vacio.bin";
    writeFile(empty, "");
    auto item = vault.quarantineFile(empty, "Test.Empty");
    ASSERT_TRUE(item.has_value());
    const fs::path restored = m_dir / "vacio_restaurado.bin";
    ASSERT_TRUE(vault.restoreFile(item->qid, restored));
    EXPECT_EQ(fs::file_size(restored), 0u);
}
