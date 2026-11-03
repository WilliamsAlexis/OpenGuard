/**
 * @file test_update.cpp
 * @brief Pruebas de importación de listas de hashes y de las restricciones de la descarga HTTPS.
 */

#include "openguard/net_update.h"
#include "openguard/signatures.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>

namespace fs = std::filesystem;

class UpdateTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_dir = fs::temp_directory_path() / "openguard_update_test";
        std::error_code ec;
        fs::remove_all(m_dir, ec);
        fs::create_directories(m_dir);
        m_db = std::make_unique<openguard::SignatureDB>(m_dir / "u.db");
    }
    void TearDown() override {
        m_db.reset();
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }
    fs::path m_dir;
    std::unique_ptr<openguard::SignatureDB> m_db;
};

TEST_F(UpdateTest, ImportsMixedHashListAndSkipsGarbage) {
    const std::string sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const std::string sha1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const std::string md5 = "cccccccccccccccccccccccccccccccc";
    const std::string text =
        "# comentario\r\n" +
        sha256 + "\r\n" +
        "\"" + sha1 + "\", \"otro campo\"\r\n" +
        md5 + " comentario al final\n" +
        "esto-no-es-un-hash\n" +
        "\n";

    size_t inserted = 0, skipped = 0;
    ASSERT_TRUE(m_db->importHashList(text, "Feed.Test", "test", inserted, skipped));
    EXPECT_EQ(inserted, 3u);
    EXPECT_EQ(skipped, 1u);

    auto bySha256 = m_db->lookup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ASSERT_TRUE(bySha256.has_value());
    EXPECT_EQ(bySha256->malwareName, "Feed.Test");
    EXPECT_EQ(bySha256->source, "test");

    EXPECT_TRUE(m_db->lookup("", sha1).has_value());
    EXPECT_TRUE(m_db->lookup("", "", md5).has_value());

    // Idempotente
    ASSERT_TRUE(m_db->importHashList(text, "Feed.Test", "test", inserted, skipped));
    EXPECT_EQ(inserted, 0u);
}

TEST(NetUpdateTest, RejectsNonHttpsAndInvalidUrls) {
    std::string body, err;
    EXPECT_FALSE(openguard::net::httpsGet("http://example.com/firmas.txt", body, err));
    EXPECT_FALSE(err.empty());

    err.clear();
    EXPECT_FALSE(openguard::net::httpsGet("esto no es una url", body, err));
    EXPECT_FALSE(err.empty());
}
