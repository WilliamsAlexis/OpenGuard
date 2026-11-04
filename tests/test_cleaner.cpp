/**
 * @file test_cleaner.cpp
 * @brief Pruebas de la limpieza de archivos temporales.
 */

#include "openguard/cleaner.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace openguard::cleaner;

namespace {

void write(const fs::path& p, const std::string& data) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << data;
}

class CleanerFixture : public ::testing::Test {
protected:
    void SetUp() override {
        m_root = fs::temp_directory_path() / ("og_clean_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
                                              "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::error_code ec;
        fs::remove_all(m_root, ec);
        fs::create_directories(m_root);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(m_root, ec);
    }
    fs::path m_root;
};

} // namespace

TEST_F(CleanerFixture, MeasuresAndCleansFilesKeepingTheRoot) {
    write(m_root / "a.tmp", std::string(100, 'x'));
    write(m_root / "sub" / "b.tmp", std::string(50, 'y'));
    write(m_root / "sub" / "deep" / "c.tmp", std::string(10, 'z'));

    const Usage u = measureDirectory(m_root, std::chrono::hours(0));
    EXPECT_EQ(u.files, 3u);
    EXPECT_EQ(u.bytes, 160u);

    const CleanResult r = cleanDirectory(m_root, std::chrono::hours(0));
    EXPECT_EQ(r.deleted, 3u);
    EXPECT_EQ(r.freed, 160u);
    EXPECT_EQ(r.failed, 0u);

    EXPECT_TRUE(fs::exists(m_root));                 // la carpeta raiz se conserva
    EXPECT_FALSE(fs::exists(m_root / "sub"));         // las subcarpetas que quedan vacias se quitan
    EXPECT_EQ(measureDirectory(m_root, std::chrono::hours(0)).files, 0u);
}

TEST_F(CleanerFixture, RecentFilesAreRespected) {
    write(m_root / "reciente.tmp", "abc");
    const CleanResult r = cleanDirectory(m_root, std::chrono::hours(24));
    EXPECT_EQ(r.deleted, 0u);
    EXPECT_TRUE(fs::exists(m_root / "reciente.tmp"));

    // Un archivo antiguo si se limpia
    const fs::path old = m_root / "antiguo.tmp";
    write(old, "abc");
    fs::last_write_time(old, fs::file_time_type::clock::now() - std::chrono::hours(72));
    const CleanResult r2 = cleanDirectory(m_root, std::chrono::hours(24));
    EXPECT_EQ(r2.deleted, 1u);
    EXPECT_FALSE(fs::exists(old));
    EXPECT_TRUE(fs::exists(m_root / "reciente.tmp"));
}

TEST_F(CleanerFixture, NamePrefixLimitsWhatIsTouched) {
    write(m_root / "thumbcache_32.db", "1234");
    write(m_root / "iconcache_32.db", "5678");
    const CleanResult r = cleanDirectory(m_root, std::chrono::hours(0), L"thumbcache_");
    EXPECT_EQ(r.deleted, 1u);
    EXPECT_FALSE(fs::exists(m_root / "thumbcache_32.db"));
    EXPECT_TRUE(fs::exists(m_root / "iconcache_32.db"));
}

TEST_F(CleanerFixture, ReadOnlyFilesAreDeleted) {
    const fs::path f = m_root / "solo_lectura.tmp";
    write(f, "dato");
    fs::permissions(f, fs::perms::owner_read, fs::perm_options::replace);
    EXPECT_EQ(cleanDirectory(m_root, std::chrono::hours(0)).deleted, 1u);
    EXPECT_FALSE(fs::exists(f));
}

TEST_F(CleanerFixture, LockedFilesAreCountedAsFailedNotDeleted) {
    const fs::path f = m_root / "en_uso.tmp";
    write(f, "dato");
    std::ofstream hold(f, std::ios::binary | std::ios::app); // el archivo queda abierto
    const CleanResult r = cleanDirectory(m_root, std::chrono::hours(0));
    EXPECT_EQ(r.deleted, 0u);
    EXPECT_EQ(r.failed, 1u);
    EXPECT_TRUE(fs::exists(f));
}

TEST_F(CleanerFixture, RefusesDriveRootsAndMissingFolders) {
    EXPECT_EQ(cleanDirectory(fs::path(L"C:\\"), std::chrono::hours(0)).deleted, 0u);
    EXPECT_EQ(cleanDirectory(fs::path{}, std::chrono::hours(0)).deleted, 0u);
    EXPECT_EQ(cleanDirectory(m_root / "no_existe", std::chrono::hours(0)).deleted, 0u);
    EXPECT_EQ(measureDirectory(fs::path(L"C:\\"), std::chrono::hours(0)).files, 0u);
}

TEST_F(CleanerFixture, CancelStopsCleaning) {
    for (int i = 0; i < 5; ++i) write(m_root / ("f" + std::to_string(i) + ".tmp"), "x");
    std::atomic<bool> cancel{true};
    EXPECT_EQ(cleanDirectory(m_root, std::chrono::hours(0), {}, &cancel).deleted, 0u);
    EXPECT_EQ(measureDirectory(m_root, std::chrono::hours(0)).files, 5u);
}

TEST(CleanerFormat, FormatsSizes) {
    EXPECT_EQ(formatBytes(512), L"512 B");
    EXPECT_EQ(formatBytes(2048), L"2.0 KB");
    EXPECT_EQ(formatBytes(5ull * 1024 * 1024 * 1024), L"5.0 GB");
}

TEST(CleanerCategories, IncludeSafeDefaultsAndOptInRisky) {
    const auto cats = categories();
    bool sawUserTemp = false;
    for (const auto& c : cats) {
        if (c.id == "user_temp") { sawUserTemp = true; EXPECT_TRUE(c.defaultSelected); EXPECT_GE(c.minAge.count(), 24); }
        if (c.id == "recycle_bin" || c.id == "browser_cache") EXPECT_FALSE(c.defaultSelected); // destructivas: solo si el usuario las marca
    }
    EXPECT_TRUE(sawUserTemp);
}
