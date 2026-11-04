/**
 * @file test_phase1.cpp
 * @brief Pruebas de la Fase 1: progreso real, macros de Office, ubicación sospechosa y programación.
 */

#include "openguard/heuristics.h"
#include "openguard/office_macros.h"
#include "openguard/scanner.h"
#include "openguard/settings.h"
#include "openguard/signatures.h"

#include <gtest/gtest.h>

#include <atomic>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::time_t makeTime(int y, int mo, int d, int h, int mi) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

std::string utf16(const std::string& ascii) {
    std::string w;
    for (char c : ascii) { w.push_back(c); w.push_back('\0'); }
    return w;
}

/// Documento OLE sintético: firma D0CF11E0... + nombres de flujos en UTF-16 (no es un documento real ni ejecutable).
std::vector<uint8_t> fakeOle(const std::string& payload) {
    std::string s("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8);
    s += std::string(512, '\0');
    s += payload;
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> fakeZip(const std::string& entryName) {
    std::string s("PK\x03\x04", 4);
    s += std::string(26, '\0');
    s += entryName;
    s += std::string(64, '\0');
    return std::vector<uint8_t>(s.begin(), s.end());
}

class Phase1Fixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = fs::temp_directory_path() / ("openguard_p1_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
        std::error_code ec;
        fs::remove_all(m_dir, ec);
        fs::create_directories(m_dir);
        m_db = std::make_shared<openguard::SignatureDB>(m_dir / "s.db");
    }
    void TearDown() override {
        m_db.reset();
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }
    void write(const fs::path& p, const std::string& s) { std::ofstream o(p, std::ios::binary); o << s; }
    void writeBytes(const fs::path& p, const std::vector<uint8_t>& b) {
        std::ofstream o(p, std::ios::binary);
        o.write(reinterpret_cast<const char*>(b.data()), static_cast<std::streamsize>(b.size()));
    }
    fs::path m_dir;
    std::shared_ptr<openguard::SignatureDB> m_db;
};

} // namespace

// ----------------------------------------------------------------------------- progreso real

TEST_F(Phase1Fixture, PrecountProgressHasRealTotalAndIsMonotonic) {
    fs::create_directories(m_dir / "datos");
    for (int i = 0; i < 40; ++i) write(m_dir / "datos" / ("f" + std::to_string(i) + ".txt"), "contenido " + std::to_string(i));

    std::mutex m;
    std::vector<openguard::ScanProgress> events;
    openguard::ScannerConfig cfg;
    cfg.precount = true;
    cfg.onProgress = [&](const openguard::ScanProgress& p) {
        std::lock_guard<std::mutex> lock(m);
        events.push_back(p);
    };

    openguard::FileScanner scanner(m_db, cfg);
    auto session = scanner.scanPath(m_dir / "datos");
    EXPECT_EQ(session.filesScanned, 40u);

    ASSERT_FALSE(events.empty());
    size_t last = 0;
    for (const auto& e : events) {
        EXPECT_EQ(e.total, 40u);          // el total es real desde el primer evento
        EXPECT_GE(e.processed, last);     // el avance nunca retrocede
        last = e.processed;
    }
    EXPECT_TRUE(events.back().finished);
    EXPECT_EQ(events.back().processed, 40u);
    EXPECT_DOUBLE_EQ(events.back().fraction(), 1.0);
}

TEST_F(Phase1Fixture, StreamingProgressReportsDiscoveredFiles) {
    fs::create_directories(m_dir / "d");
    for (int i = 0; i < 700; ++i) write(m_dir / "d" / ("f" + std::to_string(i) + ".txt"), "x" + std::to_string(i));

    openguard::ProtectionSettings unused;
    std::vector<openguard::ScanProgress> events;
    openguard::ScannerConfig cfg;
    cfg.precount = false;
    cfg.onProgress = [&](const openguard::ScanProgress& p) { events.push_back(p); };

    openguard::FileScanner scanner(m_db, cfg);
    scanner.scanPath(m_dir / "d");

    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.front().total, 0u); // en streaming el total se desconoce hasta el final
    EXPECT_TRUE(events.back().finished);
    EXPECT_EQ(events.back().total, 700u);
    EXPECT_EQ(events.back().processed, 700u);
}

TEST_F(Phase1Fixture, CancelledScanReportsFinished) {
    fs::create_directories(m_dir / "c");
    // > 512 archivos: la cancelación actúa entre lotes, así que el resultado es determinista
    for (int i = 0; i < 1100; ++i) write(m_dir / "c" / ("f" + std::to_string(i) + ".txt"), "y");

    openguard::ScanProgress finalState;
    openguard::ScannerConfig cfg;
    cfg.precount = true;
    openguard::FileScanner* self = nullptr;
    cfg.onProgress = [&](const openguard::ScanProgress& p) {
        if (self && p.processed >= 5) self->cancelScan();
        finalState = p;
    };
    openguard::FileScanner scanner(m_db, cfg);
    self = &scanner;
    auto session = scanner.scanPath(m_dir / "c");

    EXPECT_TRUE(finalState.finished);
    EXPECT_LT(session.filesScanned, 1100u); // se interrumpió antes de terminar
}

// ----------------------------------------------------------------------------- macros de Office

TEST(OfficeMacrosTest, DetectsOleVbaProjectWithAutoExecAndSuspiciousCalls) {
    const auto doc = fakeOle(utf16("_VBA_PROJECT") + utf16("AutoOpen") + "Shell(\"cmd.exe /c calc\")" + utf16("CreateObject"));
    auto rep = openguard::analyzeOfficeMacros(doc.data(), doc.size(), ".doc");
    EXPECT_TRUE(rep.isOfficeFormat);
    EXPECT_TRUE(rep.hasMacros);
    EXPECT_TRUE(rep.autoExec);
    EXPECT_FALSE(rep.suspicious.empty());
    EXPECT_GT(rep.score, 30);
}

TEST(OfficeMacrosTest, CleanOleDocumentHasNoMacros) {
    const auto doc = fakeOle(utf16("WordDocument") + utf16("SummaryInformation"));
    auto rep = openguard::analyzeOfficeMacros(doc.data(), doc.size(), ".doc");
    EXPECT_TRUE(rep.isOfficeFormat);
    EXPECT_FALSE(rep.hasMacros);
    EXPECT_EQ(rep.score, 0);
}

TEST(OfficeMacrosTest, DetectsOoxmlMacroAndDisguisedExtension) {
    const auto docm = fakeZip("word/vbaProject.bin");
    auto r1 = openguard::analyzeOfficeMacros(docm.data(), docm.size(), ".docm");
    EXPECT_TRUE(r1.hasMacros);
    EXPECT_EQ(r1.score, 20); // los .docm legítimos con macros no deben marcarse como amenaza por sí solos

    auto r2 = openguard::analyzeOfficeMacros(docm.data(), docm.size(), ".docx");
    EXPECT_TRUE(r2.hasMacros);
    EXPECT_GT(r2.score, 30); // un .docx con proyecto VBA es incoherente: posible camuflaje

    const auto plain = fakeZip("word/document.xml");
    EXPECT_FALSE(openguard::analyzeOfficeMacros(plain.data(), plain.size(), ".docx").hasMacros);
}

TEST(OfficeMacrosTest, IgnoresNonOfficeFiles) {
    const auto data = fakeOle(utf16("_VBA_PROJECT"));
    auto rep = openguard::analyzeOfficeMacros(data.data(), data.size(), ".txt");
    EXPECT_FALSE(rep.isOfficeFormat);
    EXPECT_FALSE(rep.hasMacros);
}

TEST_F(Phase1Fixture, ScannerFlagsMacroDocuments) {
    writeBytes(m_dir / "factura.doc", fakeOle(utf16("_VBA_PROJECT") + utf16("Document_Open") + "WScript.Shell powershell"));
    openguard::FileScanner scanner(m_db);

    auto res = scanner.scanFile(m_dir / "factura.doc");
    bool found = false;
    for (const auto& t : res.threats) if (t.name == "Heuristic.Office.Macro") found = true;
    EXPECT_TRUE(found);
    EXPECT_TRUE(res.isThreat());
}

// ----------------------------------------------------------------------------- ubicación sospechosa

TEST(SuspiciousLocationTest, ScoresByFolderAndIgnoresSafeOnes) {
    using openguard::HeuristicsEngine;
    auto t1 = HeuristicsEngine::suspiciousLocation(L"C:\\Users\\Ana\\AppData\\Local\\Temp\\setup.exe");
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->score, 15);
    EXPECT_EQ(t1->method, "heuristic_path");

    auto t2 = HeuristicsEngine::suspiciousLocation(L"C:\\Users\\Ana\\AppData\\Roaming\\x\\run.ps1");
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->score, 10);

    auto t3 = HeuristicsEngine::suspiciousLocation(L"C:/Users/Ana/Downloads/app.exe"); // barras normales
    ASSERT_TRUE(t3.has_value());
    EXPECT_EQ(t3->score, 5);

    EXPECT_FALSE(HeuristicsEngine::suspiciousLocation(L"C:\\Program Files\\App\\app.exe").has_value());
    EXPECT_FALSE(HeuristicsEngine::suspiciousLocation(L"C:\\Users\\Ana\\AppData\\Local\\Temp\\notas.txt").has_value());
    EXPECT_FALSE(HeuristicsEngine::suspiciousLocation(L"C:\\Users\\Ana\\Documents\\app.exe").has_value());
}

TEST_F(Phase1Fixture, ContentMatchesAreWeighedByContext) {
    int weak = 0;
    // Librerias de desarrollo: se descarta lo no critico, nunca lo critico
    EXPECT_EQ(HeuristicsEngine::weighContentMatch(L"C:\\p\\node_modules\\x\\a.js", "yara", "high", 70, weak), -1);
    EXPECT_EQ(HeuristicsEngine::weighContentMatch(L"C:\\p\\node_modules\\x\\a.js", "yara", "critical", 85, weak), 85);

    // Texto/codigo fuera de librerias: la primera coincidencia pesa 10, las siguientes 0
    weak = 0;
    EXPECT_EQ(HeuristicsEngine::weighContentMatch(L"C:\\Temp\\app.js", "yara", "high", 70, weak), 10);
    EXPECT_EQ(HeuristicsEngine::weighContentMatch(L"C:\\Temp\\app.js", "yara", "high", 70, weak), 0);

    // Binarios y firmas por hash no se alteran
    weak = 0;
    EXPECT_EQ(HeuristicsEngine::weighContentMatch(L"C:\\Temp\\app.exe", "yara", "high", 70, weak), 70);
    EXPECT_EQ(HeuristicsEngine::weighContentMatch(L"C:\\Temp\\app.js", "hash_signature", "high", 80, weak), 80);
}

TEST_F(Phase1Fixture, LocationAloneNeverReachesThreatThreshold) {
    const fs::path tempExe = m_dir / "AppData" / "Local" / "Temp" / "algo.vbs";
    fs::create_directories(tempExe.parent_path());
    write(tempExe, "' script vacio\n");
    openguard::FileScanner scanner(m_db);
    auto res = scanner.scanFile(tempExe);
    EXPECT_FALSE(res.isThreat());
}

// ----------------------------------------------------------------------------- programación

TEST(ScheduleTest, DailyDueAndCatchUp) {
    openguard::ScanSchedule s;
    s.enabled = true;
    s.frequency = "daily";
    s.hour = 9;
    s.minute = 0;

    const std::time_t now = makeTime(2026, 1, 15, 10, 0); // jueves 10:00
    EXPECT_EQ(openguard::scheduleLastDue(s, now), makeTime(2026, 1, 15, 9, 0));

    EXPECT_TRUE(openguard::scheduleIsDue(s, now, makeTime(2026, 1, 14, 9, 5)));   // ayer: pendiente
    EXPECT_FALSE(openguard::scheduleIsDue(s, now, makeTime(2026, 1, 15, 9, 5)));  // ya corrió hoy
    EXPECT_TRUE(openguard::scheduleIsDue(s, now, makeTime(2026, 1, 10, 9, 0)));   // equipo apagado varios días: puesta al día

    // Antes de la hora de hoy: la última hora debida fue ayer
    const std::time_t early = makeTime(2026, 1, 15, 8, 0);
    EXPECT_EQ(openguard::scheduleLastDue(s, early), makeTime(2026, 1, 14, 9, 0));
    EXPECT_FALSE(openguard::scheduleIsDue(s, early, makeTime(2026, 1, 14, 9, 30)));

    EXPECT_EQ(openguard::scheduleNextRun(s, now), makeTime(2026, 1, 16, 9, 0));
    EXPECT_EQ(openguard::scheduleNextRun(s, early), makeTime(2026, 1, 15, 9, 0));
}

TEST(ScheduleTest, WeeklyUsesMostRecentChosenWeekday) {
    openguard::ScanSchedule s;
    s.enabled = true;
    s.frequency = "weekly";
    s.weekday = 1; // lunes
    s.hour = 9;
    s.minute = 30;

    const std::time_t thursday = makeTime(2026, 1, 15, 10, 0);
    EXPECT_EQ(openguard::scheduleLastDue(s, thursday), makeTime(2026, 1, 12, 9, 30)); // lunes 12
    EXPECT_TRUE(openguard::scheduleIsDue(s, thursday, makeTime(2026, 1, 10, 12, 0)));
    EXPECT_FALSE(openguard::scheduleIsDue(s, thursday, makeTime(2026, 1, 12, 10, 0)));
    EXPECT_EQ(openguard::scheduleNextRun(s, thursday), makeTime(2026, 1, 19, 9, 30));
}

TEST(ScheduleTest, DisabledNeverRuns) {
    openguard::ScanSchedule s; // enabled = false
    const std::time_t now = makeTime(2026, 1, 15, 10, 0);
    EXPECT_EQ(openguard::scheduleLastDue(s, now), 0);
    EXPECT_FALSE(openguard::scheduleIsDue(s, now, 0));
    EXPECT_EQ(openguard::scheduleNextRun(s, now), 0);
}

TEST(ScheduleTest, StampRoundTrip) {
    const std::time_t t = makeTime(2026, 3, 8, 14, 5);
    EXPECT_EQ(openguard::parseLocalStamp(openguard::formatLocalStamp(t)), t);
    EXPECT_EQ(openguard::parseLocalStamp("basura"), 0);
    EXPECT_EQ(openguard::parseLocalStamp(""), 0);
    EXPECT_TRUE(openguard::formatLocalStamp(0).empty());
}

TEST_F(Phase1Fixture, ScheduleIsPersistedInSettings) {
    openguard::ProtectionSettings s;
    s.schedule.enabled = true;
    s.schedule.type = "full";
    s.schedule.frequency = "weekly";
    s.schedule.hour = 3;
    s.schedule.minute = 45;
    s.schedule.weekday = 6;
    ASSERT_TRUE(s.save(m_dir / "c.ini"));

    auto loaded = openguard::ProtectionSettings::load(m_dir / "c.ini");
    EXPECT_TRUE(loaded.schedule.enabled);
    EXPECT_EQ(loaded.schedule.type, "full");
    EXPECT_EQ(loaded.schedule.frequency, "weekly");
    EXPECT_EQ(loaded.schedule.hour, 3);
    EXPECT_EQ(loaded.schedule.minute, 45);
    EXPECT_EQ(loaded.schedule.weekday, 6);

    EXPECT_FALSE(openguard::ProtectionSettings::load(m_dir / "no_existe.ini").schedule.enabled); // valor por defecto
}
