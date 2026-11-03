/**
 * @file test_realtime_pe.cpp
 * @brief Pruebas del monitor en tiempo real, del analizador PE (sobre el propio ejecutable) y de rutas.
 */

#include "openguard/paths.h"
#include "openguard/pe_analyzer.h"
#include "openguard/realtime_monitor.h"

#include <gtest/gtest.h>

#include <windows.h>

#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <string>
#include <thread>

namespace fs = std::filesystem;

// ------------------------------------------------------------------ rutas

TEST(PathsTest, Utf8RoundTripPreservesUnicode) {
    const fs::path original(L"C:\\Usuarios\\Jos\u00E9\\documentos_\u65E5\u672C\\\u00F1and\u00FA.txt");
    const std::string utf8 = openguard::paths::toUtf8(original);
    EXPECT_FALSE(utf8.empty());
    EXPECT_EQ(openguard::paths::fromUtf8(utf8), original);
}

TEST(PathsTest, DataDirHonorsEnvironmentOverride) {
    const fs::path custom = fs::temp_directory_path() / "openguard_datadir_test";
    SetEnvironmentVariableW(L"OPENGUARD_DATA_DIR", custom.c_str());

    EXPECT_EQ(openguard::paths::dataDir(), custom);
    EXPECT_TRUE(fs::exists(custom));
    EXPECT_EQ(openguard::paths::databasePath(), custom / "hashes.db");

    SetEnvironmentVariableW(L"OPENGUARD_DATA_DIR", nullptr);
    std::error_code ec;
    fs::remove_all(custom, ec);
}

// ------------------------------------------------------------------ PE

namespace {
fs::path selfExecutable() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return fs::path(buf);
}
} // namespace

TEST(PEAnalyzerTest, ParsesOwnExecutableStructure) {
    openguard::PEAnalyzer analyzer;
    const auto report = analyzer.analyze(selfExecutable());

    ASSERT_TRUE(report.isValidPE);
    EXPECT_TRUE(report.is64Bit);
    EXPECT_FALSE(report.isDLL);
    EXPECT_GE(report.sections.size(), 2u);
    EXPECT_GT(report.overallEntropy, 0.0);
    EXPECT_NE(report.entryPointRVA, 0u);
    EXPECT_FALSE(report.entryPointSection.empty());

    // Se debe haber recorrido la IAT real: kernel32 la importa cualquier programa de Windows
    bool hasKernel32 = false;
    for (const auto& dll : report.importedDLLs) {
        std::string lower = dll;
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower.rfind("kernel32", 0) == 0) hasKernel32 = true;
    }
    EXPECT_TRUE(hasKernel32);
}

TEST(PEAnalyzerTest, BenignProgramIsNotFlaggedAsMalicious) {
    openguard::PEAnalyzer analyzer;
    const auto report = analyzer.analyze(selfExecutable());
    ASSERT_TRUE(report.isValidPE);
    // Un programa legítimo (aunque sin firmar) no debe superar el umbral de amenaza (30)
    EXPECT_LE(report.heuristicScore, 30) << "Falso positivo sobre un binario benigno";
}

TEST(PEAnalyzerTest, NonPEFileIsRejected) {
    const fs::path file = fs::temp_directory_path() / "openguard_nope.exe";
    {
        std::ofstream ofs(file, std::ios::binary);
        ofs << "esto no es un ejecutable portable";
    }

    openguard::PEAnalyzer analyzer;
    EXPECT_FALSE(analyzer.analyze(file).isValidPE);

    std::error_code ec;
    fs::remove(file, ec);
}

TEST(PEAnalyzerTest, TruncatedPEDoesNotCrash) {
    // Cabecera MZ válida con e_lfanew apuntando fuera del archivo
    std::string data(64, '\0');
    data[0] = 'M';
    data[1] = 'Z';
    data[0x3C] = static_cast<char>(0xFF);
    data[0x3D] = static_cast<char>(0xFF);

    const fs::path file = fs::temp_directory_path() / "openguard_truncated.exe";
    {
        std::ofstream ofs(file, std::ios::binary);
        ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    openguard::PEAnalyzer analyzer;
    EXPECT_FALSE(analyzer.analyze(file).isValidPE);

    std::error_code ec;
    fs::remove(file, ec);
}

// ------------------------------------------------------------------ monitor en tiempo real

TEST(RealtimeMonitorTest, NotifiesNewFilesAfterQuietPeriod) {
    const fs::path dir = fs::temp_directory_path() / "openguard_monitor_test";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir / "sub");

    std::mutex m;
    std::set<fs::path> seen;

    openguard::RealtimeMonitor monitor(std::chrono::milliseconds(200));
    ASSERT_TRUE(monitor.start({dir}, [&](const fs::path& p) {
        std::lock_guard<std::mutex> lock(m);
        seen.insert(p);
    }));
    EXPECT_TRUE(monitor.isRunning());
    EXPECT_EQ(monitor.watchedCount(), 1u);

    const fs::path target = dir / "sub" / "nuevo.exe";
    {
        std::ofstream ofs(target, std::ios::binary);
        ofs << "contenido";
        ofs.flush();
        ofs << " adicional";
    }

    bool found = false;
    for (int i = 0; i < 100 && !found; ++i) { // Hasta 10 s
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::lock_guard<std::mutex> lock(m);
        found = seen.count(target) > 0;
    }

    monitor.stop();
    EXPECT_FALSE(monitor.isRunning());
    EXPECT_TRUE(found) << "No se notifico el archivo creado en una subcarpeta";

    fs::remove_all(dir, ec);
}

TEST(RealtimeMonitorTest, StartFailsWithoutValidDirectories) {
    openguard::RealtimeMonitor monitor;
    EXPECT_FALSE(monitor.start({fs::path("Z:\\directorio\\que\\no\\existe")}, [](const fs::path&) {}));
    EXPECT_FALSE(monitor.isRunning());
    monitor.stop(); // Idempotente
}

TEST(RealtimeMonitorTest, StopIsIdempotentAndRestartable) {
    const fs::path dir = fs::temp_directory_path() / "openguard_monitor_restart";
    std::error_code ec;
    fs::create_directories(dir);

    openguard::RealtimeMonitor monitor(std::chrono::milliseconds(100));
    ASSERT_TRUE(monitor.start({dir}, [](const fs::path&) {}));
    monitor.stop();
    monitor.stop();
    ASSERT_TRUE(monitor.start({dir}, [](const fs::path&) {}));
    monitor.stop();

    fs::remove_all(dir, ec);
}
