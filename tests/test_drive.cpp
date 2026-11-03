/**
 * @file test_drive.cpp
 * @brief Pruebas de la inspección/reparación de unidades externas y de los nuevos ajustes (USB y descargas).
 */

#include "openguard/drive_tools.h"
#include "openguard/settings.h"

#include <gtest/gtest.h>

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

class DriveFixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_root = fs::temp_directory_path() / ("openguard_drive_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        std::error_code ec;
        clearAttrs();
        fs::remove_all(m_root, ec);
        fs::create_directories(m_root);
    }
    void TearDown() override {
        clearAttrs();
        std::error_code ec;
        fs::remove_all(m_root, ec);
    }
    /// Quita atributos ocultos/sistema para poder borrar todo al terminar.
    void clearAttrs() {
        std::error_code ec;
        if (!fs::exists(m_root, ec)) return;
        for (fs::recursive_directory_iterator it(m_root, ec), end; !ec && it != end; it.increment(ec)) {
            SetFileAttributesW(it->path().c_str(), FILE_ATTRIBUTE_NORMAL);
        }
    }
    void write(const fs::path& p, const std::string& s) { std::ofstream o(p, std::ios::binary); o << s; }
    void hide(const fs::path& p, bool system = false) {
        SetFileAttributesW(p.c_str(), FILE_ATTRIBUTE_HIDDEN | (system ? FILE_ATTRIBUTE_SYSTEM : 0));
    }
    static bool hasCode(const openguard::DriveInspection& i, const std::string& code) {
        for (const auto& f : i.findings) if (f.code == code) return true;
        return false;
    }
    static bool isHidden(const fs::path& p) {
        const DWORD a = GetFileAttributesW(p.c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_HIDDEN) != 0;
    }
    fs::path m_root;
};

} // namespace

TEST_F(DriveFixture, DetectsShortcutVirusAutorunAndLookalikes) {
    write(m_root / "autorun.inf", "[autorun]\r\nopen=virus.exe\r\nicon=virus.exe\r\n");

    fs::create_directories(m_root / "Fotos");
    write(m_root / "Fotos" / "a.jpg", "x");
    hide(m_root / "Fotos");
    write(m_root / "Fotos.lnk", "LNK /c cmd.exe /c start Fotos & virus.exe"); // sin bytes nulos: std::string los truncaría

    fs::create_directories(m_root / "Tareas");
    write(m_root / "Tareas.exe", "MZ");
    write(m_root / "nota.txt", "hola");
    hide(m_root / "nota.txt");
    write(m_root / "readme.txt", "normal");

    fs::create_directories(m_root / "System Volume Information");
    hide(m_root / "System Volume Information", true);

    auto ins = openguard::inspectDrive(m_root);
    EXPECT_TRUE(ins.hasAutorun);
    EXPECT_TRUE(ins.shortcutVirusSuspected);
    EXPECT_TRUE(hasCode(ins, "autorun"));
    EXPECT_TRUE(hasCode(ins, "shortcut_virus"));
    EXPECT_TRUE(hasCode(ins, "exe_lookalike"));
    EXPECT_TRUE(hasCode(ins, "hidden"));
    EXPECT_GE(ins.hiddenItems, 2u);
    EXPECT_TRUE(ins.needsRepair());

    // Los elementos propios del sistema no se reportan como ocultos del usuario
    for (const auto& f : ins.findings) {
        EXPECT_EQ(f.path.filename().wstring().find(L"System Volume"), std::wstring::npos);
    }
}

TEST_F(DriveFixture, RepairRestoresVisibilityAndRemovesMaliciousShortcuts) {
    write(m_root / "autorun.inf", "[autorun]\r\nshellexecute=virus.exe\r\n");
    fs::create_directories(m_root / "Fotos");
    hide(m_root / "Fotos");
    write(m_root / "Fotos.lnk", "LNK /c wscript.exe //e:vbscript x.vbs");
    write(m_root / "nota.txt", "hola");
    hide(m_root / "nota.txt", true);
    write(m_root / "Tareas.exe", "MZ");
    fs::create_directories(m_root / "Tareas");
    fs::create_directories(m_root / "System Volume Information");
    hide(m_root / "System Volume Information", true);

    auto ins = openguard::inspectDrive(m_root);
    auto res = openguard::repairDrive(ins);

    EXPECT_EQ(res.failed, 0u);
    EXPECT_GE(res.removedAutorun, 1u);
    EXPECT_GE(res.removedShortcuts, 1u);
    EXPECT_GE(res.unhidden, 2u);

    EXPECT_FALSE(fs::exists(m_root / "autorun.inf"));
    EXPECT_FALSE(fs::exists(m_root / "Fotos.lnk"));
    EXPECT_TRUE(fs::exists(m_root / "Fotos"));          // los datos del usuario se conservan
    EXPECT_FALSE(isHidden(m_root / "Fotos"));
    EXPECT_FALSE(isHidden(m_root / "nota.txt"));
    EXPECT_TRUE(fs::exists(m_root / "Tareas.exe"));      // el ejecutable no se borra: lo trata el análisis
    EXPECT_TRUE(isHidden(m_root / "System Volume Information")); // el sistema se respeta

    // Tras reparar, la unidad ya no presenta síntomas
    EXPECT_TRUE(openguard::inspectDrive(m_root).findings.empty() ||
                !openguard::inspectDrive(m_root).hasAutorun);
}

TEST_F(DriveFixture, CleanDriveHasNoFindings) {
    write(m_root / "informe.docx", "contenido");
    write(m_root / "musica.mp3", "audio");
    fs::create_directories(m_root / "Vacaciones");
    auto ins = openguard::inspectDrive(m_root);
    EXPECT_FALSE(ins.needsRepair());
    EXPECT_FALSE(ins.hasAutorun);
    EXPECT_FALSE(ins.shortcutVirusSuspected);
}

TEST_F(DriveFixture, HarmlessAutorunAndSingleHiddenFileAreNotFlagged) {
    write(m_root / "autorun.inf", "[autorun]\r\nlabel=Mi memoria\r\n"); // solo etiqueta: no ejecuta nada
    write(m_root / "secreto.txt", "x");
    hide(m_root / "secreto.txt");

    auto ins = openguard::inspectDrive(m_root);
    EXPECT_FALSE(ins.hasAutorun);
    EXPECT_FALSE(hasCode(ins, "hidden")); // un único archivo oculto sin otros indicios es normal
    EXPECT_FALSE(ins.needsRepair());
}

TEST_F(DriveFixture, ManyHiddenItemsAreFlagevenWithoutShortcuts) {
    for (int i = 0; i < 4; ++i) {
        const fs::path p = m_root / ("carpeta" + std::to_string(i));
        fs::create_directories(p);
        hide(p);
    }
    auto ins = openguard::inspectDrive(m_root);
    EXPECT_EQ(ins.hiddenItems, 4u);
    EXPECT_TRUE(hasCode(ins, "hidden"));

    openguard::repairDrive(ins);
    EXPECT_FALSE(isHidden(m_root / "carpeta0"));
}

TEST(DriveToolsTest, MissingRootIsHandled) {
    auto ins = openguard::inspectDrive("Z:\\no\\existe");
    EXPECT_FALSE(ins.needsRepair());
}

// ----------------------------------------------------------------------------- ajustes de USB y descargas

TEST_F(DriveFixture, UsbModeAndDownloadScanSettings) {
    const fs::path ini = m_root / "c.ini";

    auto defaults = openguard::ProtectionSettings::load(ini);
    EXPECT_EQ(defaults.usbMode, "ask");
    EXPECT_TRUE(defaults.scanDownloads);

    // Compatibilidad: una configuración antigua con scan_usb=0 equivale a "off"
    WritePrivateProfileStringW(L"service", L"scan_usb", L"0", ini.c_str());
    EXPECT_EQ(openguard::ProtectionSettings::load(ini).usbMode, "off");

    openguard::ProtectionSettings s;
    s.usbMode = "auto";
    s.scanDownloads = false;
    ASSERT_TRUE(s.save(ini));
    auto loaded = openguard::ProtectionSettings::load(ini);
    EXPECT_EQ(loaded.usbMode, "auto");
    EXPECT_TRUE(loaded.scanUsb);
    EXPECT_FALSE(loaded.scanDownloads);

    s.usbMode = "valor invalido";
    ASSERT_TRUE(s.save(ini));
    EXPECT_EQ(openguard::ProtectionSettings::load(ini).usbMode, "ask"); // valores inválidos se normalizan

    s.usbMode = "off";
    ASSERT_TRUE(s.save(ini));
    EXPECT_FALSE(openguard::ProtectionSettings::load(ini).scanUsb);
}
