/**
 * @file test_yara.cpp
 * @brief Pruebas del intérprete YARA embebido y de su integración en el escáner.
 */

#include "openguard/scanner.h"
#include "openguard/signatures.h"
#include "openguard/yara_lite.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

std::vector<openguard::YaraMatch> scanText(const openguard::YaraLite& y, const std::string& s) {
    return y.scan(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

bool hasRule(const std::vector<openguard::YaraMatch>& m, const std::string& name) {
    for (const auto& x : m) if (x.rule == name) return true;
    return false;
}

} // namespace

TEST(YaraLiteTest, ShippedRulesAreAllSupported) {
    openguard::YaraLite y;
    const auto dir = fs::path(OPENGUARD_SOURCE_DIR) / "signatures" / "yara_rules";
    const size_t loaded = y.loadDirectory(dir);
    EXPECT_GE(loaded, 10u);
    EXPECT_EQ(y.skippedCount(), 0u) << "Alguna regla distribuida usa construcciones no soportadas";
}

TEST(YaraLiteTest, MatchesTextStringsWithQuantifier) {
    openguard::YaraLite y;
    ASSERT_EQ(y.loadFromString(R"(
rule Note {
    meta:
        description = "nota de rescate"
        severity = "critical"
    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $b = "Send Bitcoin" nocase
        $c = ".onion" nocase
    condition:
        2 of them
})"), 1u);

    auto m = scanText(y, "hello your files have been encrypted. please send bitcoin now");
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m[0].rule, "Note");
    EXPECT_EQ(m[0].severity, "critical");
    EXPECT_EQ(m[0].description, "nota de rescate");

    EXPECT_TRUE(scanText(y, "solo menciona Send Bitcoin una vez").empty());
}

TEST(YaraLiteTest, NocaseIsHonoredAndCaseSensitiveByDefault) {
    openguard::YaraLite y2;
    ASSERT_EQ(y2.loadFromString(R"(
rule Sensitive {
    strings:
        $a = "Secret"
    condition:
        $a
}
rule Insensitive {
    strings:
        $a = "Secret" nocase
    condition:
        $a
}
)"), 2u);
    auto m = scanText(y2, "contiene SECRET en mayusculas");
    EXPECT_TRUE(hasRule(m, "Insensitive"));
    EXPECT_FALSE(hasRule(m, "Sensitive"));
}

TEST(YaraLiteTest, BooleanConditionsAndParentheses) {
    openguard::YaraLite y2;
    ASSERT_EQ(y2.loadFromString(R"(
rule Combo {
    strings:
        $reg1 = "CurrentVersion\\Run" nocase
        $run1 = "WScript.Shell" nocase
        $run2 = "RegWrite" nocase
    condition:
        $reg1 and ($run1 or $run2)
})"), 1u);
    EXPECT_TRUE(hasRule(scanText(y2, "HKCU\\...\\CurrentVersion\\Run ... wscript.shell"), "Combo"));
    EXPECT_FALSE(hasRule(scanText(y2, "solo CurrentVersion\\Run"), "Combo"));
}

TEST(YaraLiteTest, HexStringsAndRegexAndFilesize) {
    openguard::YaraLite y;
    ASSERT_EQ(y.loadFromString(R"(
rule Hex {
    strings:
        $sc = { fc e8 ?? 00 00 00 60 }
    condition:
        any of them
}
rule Rx {
    strings:
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/ ascii
    condition:
        $b64 and filesize < 1KB
}
)"), 2u);

    const std::string shell("\x90\x90\xfc\xe8\x82\x00\x00\x00\x60\x89", 10);
    EXPECT_TRUE(hasRule(scanText(y, shell), "Hex"));
    EXPECT_FALSE(hasRule(scanText(y, std::string("\xfc\xe8\x82\x01\x00\x00\x60", 7)), "Hex"));

    const std::string b64 = "dato " + std::string(60, 'A') + "==";
    EXPECT_TRUE(hasRule(scanText(y, b64), "Rx"));
    EXPECT_FALSE(hasRule(scanText(y, b64 + std::string(2000, ' ')), "Rx")); // filesize >= 1KB
}

TEST(YaraLiteTest, UnsupportedRulesAreSkippedNotMatched) {
    openguard::YaraLite y;
    EXPECT_EQ(y.loadFromString(R"(
rule Uses_Module {
    strings:
        $a = "abc"
    condition:
        $a and uint16(0) == 0x5A4D
}
)"), 0u);
    EXPECT_EQ(y.skippedCount(), 1u);
    EXPECT_TRUE(scanText(y, "abc").empty());
}

TEST(YaraLiteTest, CommentsAndUrlsInStringsAreHandled) {
    openguard::YaraLite y;
    ASSERT_EQ(y.loadFromString(R"(
/* bloque
   de comentario */
rule Url {
    // comentario de linea
    strings:
        $u = "http://evil.example/payload" // comentario tras la cadena
    condition:
        $u
}
)"), 1u);
    EXPECT_TRUE(hasRule(scanText(y, "GET http://evil.example/payload HTTP/1.1"), "Url"));
}

TEST(YaraLiteTest, ScannerReportsYaraDetections) {
    const fs::path dir = fs::temp_directory_path() / "openguard_yara_scan_test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir / "rules");
    {
        std::ofstream r(dir / "rules" / "t.yar");
        r << "rule Test_Marker {\n    meta:\n        severity = \"critical\"\n    strings:\n"
             "        $a = \"OPENGUARD_YARA_MARKER_123\"\n    condition:\n        $a\n}\n";
    }
    {
        std::ofstream f(dir / "muestra.bin", std::ios::binary);
        f << "xx OPENGUARD_YARA_MARKER_123 yy";
    }

    openguard::ScannerConfig cfg;
    cfg.yaraRulesDir = dir / "rules";
    auto db = std::make_shared<openguard::SignatureDB>(dir / "s.db");
    openguard::FileScanner scanner(db, cfg);
    EXPECT_EQ(scanner.yaraRuleCount(), 1u);

    auto res = scanner.scanFile(dir / "muestra.bin");
    EXPECT_TRUE(res.isThreat());
    ASSERT_FALSE(res.threats.empty());
    bool found = false;
    for (const auto& t : res.threats) if (t.name == "YARA.Test_Marker" && t.method == "yara") found = true;
    EXPECT_TRUE(found);
}
