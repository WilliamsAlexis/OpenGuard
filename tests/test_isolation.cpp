/**
 * @file test_isolation.cpp
 * @brief Pruebas de la Fase 0c: análisis de contenido en memoria y proceso trabajador aislado.
 */

#include "openguard/content_analysis.h"
#include "openguard/crypto_utils.h"
#include "openguard/isolated_scan.h"
#include "openguard/scanner.h"
#include "openguard/signatures.h"
#include "openguard/yara_lite.h"

#include <gtest/gtest.h>

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace fs = std::filesystem;

namespace {

const char kEicarText[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

class IsoFixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = fs::temp_directory_path() / ("openguard_iso_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        std::error_code ec;
        fs::remove_all(m_dir, ec);
        fs::create_directories(m_dir);
        m_db = std::make_shared<openguard::SignatureDB>(m_dir / "s.db");
        m_db->seedEicar();
    }
    void TearDown() override {
        m_db.reset();
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }
    void write(const fs::path& p, const std::string& s) {
        std::ofstream o(p, std::ios::binary);
        o << s;
    }
    openguard::IsolatedScanner::Options options() const {
        openguard::IsolatedScanner::Options o;
        o.workerExe = fs::path(OPENGUARD_WORKER_PATH);
        o.timeout = std::chrono::seconds(60);
        return o;
    }
    fs::path m_dir;
    std::shared_ptr<openguard::SignatureDB> m_db;
};

} // namespace

// ----------------------------------------------------------------------------- análisis de contenido

TEST(ContentAnalysisTest, HashesMatchFileHashesAndEicarIsHashable) {
    const std::string eicar(kEicarText);
    auto result = openguard::analyzeContent(bytes(eicar), "eicar.com", nullptr);
    ASSERT_TRUE(result.ok);
    EXPECT_EQ(result.sha256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    EXPECT_EQ(result.sha1, "3395856ce81f2b7382dee72602f798b642f14140");
    EXPECT_EQ(result.md5, "44d88612fea8a8f36de82e1278abb02f");
    EXPECT_TRUE(result.threats.empty());
}

TEST(ContentAnalysisTest, DetectsYaraAndScriptHeuristicsInMemory) {
    openguard::YaraLite yara;
    ASSERT_EQ(yara.loadFromString("rule Marker {\n    meta:\n        severity = \"high\"\n    strings:\n"
                                  "        $a = \"MARCADOR_DE_PRUEBA_XYZ\"\n    condition:\n        $a\n}\n"), 1u);

    auto r1 = openguard::analyzeContent(bytes("hola MARCADOR_DE_PRUEBA_XYZ adios"), "x.bin", &yara);
    ASSERT_TRUE(r1.ok);
    ASSERT_EQ(r1.threats.size(), 1u);
    EXPECT_EQ(r1.threats[0].name, "YARA.Marker");
    EXPECT_EQ(r1.threats[0].method, "yara");

    const std::string ps = "vssadmin.exe delete shadows /all /quiet\n";
    auto r2 = openguard::analyzeContent(bytes(ps), "limpia_sombras.bat", nullptr);
    ASSERT_TRUE(r2.ok);
    ASSERT_FALSE(r2.threats.empty());
    EXPECT_EQ(r2.threats[0].method, "heuristic_script");
}

TEST(ContentAnalysisTest, AnalyzesPeStructureFromMemory) {
    wchar_t self[MAX_PATH]{};
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::ifstream in(fs::path(self), std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    ASSERT_GT(data.size(), 1024u);

    auto r = openguard::analyzeContent(data, "programa.exe", nullptr);
    ASSERT_TRUE(r.ok);
    EXPECT_TRUE(r.isPE);
    EXPECT_LE(r.peScore, 30); // sin el ajuste de firma: un binario benigno no debe parecer sospechoso
}

TEST(ContentAnalysisTest, JsonRoundTripAndRejectsGarbage) {
    openguard::ContentAnalysis a;
    a.ok = true;
    a.sha256 = "aa";
    a.isPE = true;
    a.peScore = 42;
    a.peReasons = {"razon uno", "razón dos"};
    a.threats.push_back({"YARA.Test", "yara", "high", 70, "detalle"});

    openguard::ContentAnalysis b;
    ASSERT_TRUE(openguard::contentAnalysisFromJson(openguard::contentAnalysisToJson(a), b));
    EXPECT_TRUE(b.ok);
    EXPECT_EQ(b.peScore, 42);
    ASSERT_EQ(b.peReasons.size(), 2u);
    EXPECT_EQ(b.peReasons[1], "razón dos");
    ASSERT_EQ(b.threats.size(), 1u);
    EXPECT_EQ(b.threats[0].score, 70);

    openguard::ContentAnalysis c;
    EXPECT_FALSE(openguard::contentAnalysisFromJson("no es json", c));
    EXPECT_FALSE(openguard::contentAnalysisFromJson("[1,2,3]", c));
    EXPECT_FALSE(openguard::contentAnalysisFromJson(R"({"ok": true, "threats": [{"score": "texto"}]})", c));

    // Puntuaciones fuera de rango se acotan (el trabajador no es de confianza)
    ASSERT_TRUE(openguard::contentAnalysisFromJson(R"({"ok": true, "pe_score": 99999, "threats": [{"name":"x","score": -50}]})", c));
    EXPECT_EQ(c.peScore, 100);
    EXPECT_EQ(c.threats[0].score, 0);
}

// ----------------------------------------------------------------------------- proceso aislado

TEST_F(IsoFixture, WorkerIsAvailableAndDetectsEicarThroughHashSignature) {
    openguard::IsolatedScanner scanner(m_db, options());
    ASSERT_TRUE(scanner.available()) << "No se encontro openguard_worker.exe en " << OPENGUARD_WORKER_PATH;

    const fs::path file = m_dir / "eicar.com";
    write(file, kEicarText);

    auto result = scanner.scan(file);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->skipped);
    EXPECT_EQ(result->sha256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    EXPECT_TRUE(result->isThreat());

    bool signatureHit = false;
    for (const auto& t : result->threats) if (t.method == "hash_signature") signatureHit = true;
    EXPECT_TRUE(signatureHit);
}

TEST_F(IsoFixture, WorkerReturnsCleanForHarmlessFileAndMatchesInProcessHashes) {
    openguard::IsolatedScanner scanner(m_db, options());
    const fs::path file = m_dir / "notas.txt";
    write(file, "texto inofensivo para el analisis aislado");

    auto result = scanner.scan(file);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->isThreat());
    EXPECT_EQ(result->sha256, openguard::CryptoUtils::computeSha256(file));
}

TEST_F(IsoFixture, WorkerFindsScriptHeuristicsAndDoubleExtension) {
    openguard::IsolatedScanner scanner(m_db, options());

    const fs::path bat = m_dir / "ransom_prep.bat";
    write(bat, "@echo off\nvssadmin.exe delete shadows /all /quiet\n");
    auto r1 = scanner.scan(bat);
    ASSERT_TRUE(r1.has_value());
    EXPECT_TRUE(r1->isThreat());

    const fs::path dbl = m_dir / "factura.pdf.exe";
    write(dbl, "MZ");
    auto r2 = scanner.scan(dbl);
    ASSERT_TRUE(r2.has_value());
    bool found = false;
    for (const auto& t : r2->threats) if (t.name == "Heuristic.DoubleExtension") found = true;
    EXPECT_TRUE(found);
}

TEST_F(IsoFixture, MissingOrLockedFilesAreSkippedNotCrashed) {
    openguard::IsolatedScanner scanner(m_db, options());
    auto result = scanner.scan(m_dir / "no_existe.bin");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->skipped);
    EXPECT_EQ(result->error.rfind("Error de lectura", 0), 0u); // el servicio reintenta con este prefijo
}

TEST_F(IsoFixture, MissingWorkerReportsUnavailableAndNullopt) {
    openguard::IsolatedScanner::Options o;
    o.workerExe = m_dir / "no_existe_worker.exe";
    openguard::IsolatedScanner scanner(m_db, o);
    EXPECT_FALSE(scanner.available());

    const fs::path file = m_dir / "a.txt";
    write(file, "contenido");
    EXPECT_FALSE(scanner.scan(file).has_value()); // el llamador debe usar el respaldo en proceso
}

TEST_F(IsoFixture, OversizedFilesAreSkipped) {
    auto o = options();
    o.maxFileBytes = 16;
    openguard::IsolatedScanner scanner(m_db, o);
    const fs::path file = m_dir / "grande.bin";
    write(file, std::string(1024, 'A'));

    auto result = scanner.scan(file);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->skipped);
}

TEST_F(IsoFixture, FileScannerDelegatesToCustomAnalyzer) {
    openguard::IsolatedScanner iso(m_db, options());
    openguard::ScannerConfig cfg;
    cfg.threadCount = 2;
    cfg.customAnalyzer = [&iso](const fs::path& p) -> openguard::ScanResult {
        if (auto r = iso.scan(p)) return *r;
        return {};
    };
    openguard::FileScanner scanner(m_db, cfg);

    write(m_dir / "eicar.com", kEicarText);
    write(m_dir / "limpio.txt", "nada que ver");

    auto session = scanner.scanPath(m_dir);
    EXPECT_GE(session.filesScanned, 2u);
    EXPECT_GE(session.threatsFound, 1u);
}
