/**
 * @file test_app_update.cpp
 * @brief Pruebas de la comparación de versiones y del análisis de la respuesta de GitHub Releases.
 */

#include "openguard/app_update.h"

#include <gtest/gtest.h>

using openguard::isNewerVersion;
using openguard::parseLatestRelease;

TEST(AppUpdateTest, VersionComparison) {
    EXPECT_TRUE(isNewerVersion("0.3.0", "0.2.0"));
    EXPECT_TRUE(isNewerVersion("v1.0.0", "0.9.9"));
    EXPECT_TRUE(isNewerVersion("0.2.1", "0.2.0"));
    EXPECT_TRUE(isNewerVersion("0.10.0", "0.9.0")); // comparación numérica, no de texto
    EXPECT_FALSE(isNewerVersion("0.2.0", "0.2.0"));
    EXPECT_FALSE(isNewerVersion("0.1.9", "0.2.0"));
    EXPECT_FALSE(isNewerVersion("v0.2", "0.2.0"));
}

TEST(AppUpdateTest, ParsesReleaseWithInstallerAndHash) {
    const std::string json = R"({
      "tag_name": "v0.3.0",
      "html_url": "https://github.com/WilliamsAlexis/OpenGuard/releases/tag/v0.3.0",
      "body": "Nuevas funciones",
      "assets": [
        {"name": "OpenGuard_Setup_v0.3.0.exe", "browser_download_url": "https://example.com/OpenGuard_Setup_v0.3.0.exe"},
        {"name": "OpenGuard_Setup_v0.3.0.exe.sha256", "browser_download_url": "https://example.com/OpenGuard_Setup_v0.3.0.exe.sha256"},
        {"name": "otro.zip", "browser_download_url": "https://example.com/otro.zip"}
      ]
    })";

    const auto info = parseLatestRelease(json, "0.2.0");
    ASSERT_TRUE(info.ok);
    EXPECT_TRUE(info.available);
    EXPECT_EQ(info.latestVersion, "0.3.0");
    EXPECT_EQ(info.installerName, "OpenGuard_Setup_v0.3.0.exe");
    EXPECT_EQ(info.installerUrl, "https://example.com/OpenGuard_Setup_v0.3.0.exe");
    EXPECT_EQ(info.sha256Url, "https://example.com/OpenGuard_Setup_v0.3.0.exe.sha256");
    EXPECT_EQ(info.notes, "Nuevas funciones");
}

TEST(AppUpdateTest, SameVersionIsNotAvailable) {
    const auto info = parseLatestRelease(R"({"tag_name": "v0.2.0", "assets": []})", "0.2.0");
    ASSERT_TRUE(info.ok);
    EXPECT_FALSE(info.available);
}

TEST(AppUpdateTest, InvalidResponsesAreRejected) {
    EXPECT_FALSE(parseLatestRelease("no es json", "0.2.0").ok);
    EXPECT_FALSE(parseLatestRelease("[]", "0.2.0").ok);
    const auto noTag = parseLatestRelease(R"({"assets": []})", "0.2.0");
    EXPECT_FALSE(noTag.ok);
    EXPECT_FALSE(noTag.error.empty());
}
