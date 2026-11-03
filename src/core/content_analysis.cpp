/**
 * @file content_analysis.cpp
 * @brief Implementación del análisis de contenido en memoria y de su serialización.
 */

#include "openguard/content_analysis.h"
#include "openguard/crypto_utils.h"
#include "openguard/heuristics.h"
#include "openguard/paths.h"
#include "openguard/pe_analyzer.h"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace openguard {

namespace {

constexpr size_t kYaraScanBytes = 4 * 1024 * 1024;

bool isPeExtension(const std::string& ext) {
    return ext == ".exe" || ext == ".dll" || ext == ".sys" || ext == ".scr" || ext == ".ocx";
}

bool isScriptExtension(const std::string& ext) {
    return ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".bat" || ext == ".cmd" || ext == ".hta" || ext == ".wsf";
}

} // namespace

ContentAnalysis analyzeContent(const std::vector<uint8_t>& data, const std::filesystem::path& displayPath,
                               const YaraLite* yara) {
    ContentAnalysis out;

    const FileHashes hashes = CryptoUtils::computeBufferHashes(data.data(), data.size());
    if (!hashes.success) {
        out.error = "No se pudieron calcular los hashes";
        return out;
    }
    out.sha256 = hashes.sha256;
    out.sha1 = hashes.sha1;
    out.md5 = hashes.md5;

    // Reglas YARA sobre los primeros 4 MB (misma política que FileScanner)
    if (yara && yara->ruleCount() > 0 && !data.empty()) {
        for (const auto& m : yara->scan(data.data(), std::min(data.size(), kYaraScanBytes))) {
            int score = 45;
            if (m.severity == "critical") score = 85;
            else if (m.severity == "high") score = 70;
            else if (m.severity == "low") score = 20;
            out.threats.push_back({"YARA." + m.rule, "yara", m.severity, score, m.description});
        }
    }

    const std::string ext = paths::extensionLower(displayPath);

    if (isPeExtension(ext)) {
        PEAnalyzer analyzer;
        const PEReport report = analyzer.analyzeBuffer(data, nullptr); // sin firma: la completa el servicio
        if (report.isValidPE) {
            out.isPE = true;
            out.peScore = report.heuristicScore;
            out.peReasons = report.anomalyReasons;
            out.peDetectedPacker = report.detectedPacker;
        }
    } else if (isScriptExtension(ext)) {
        ScriptAnalyzer analyzer;
        const size_t n = std::min<size_t>(data.size(), 512 * 1024);
        const ScriptReport report = analyzer.analyzeContent(
            std::string(reinterpret_cast<const char*>(data.data()), n), displayPath);
        ScanResult tmp;
        HeuristicsEngine::addScriptThreat(report, tmp);
        for (auto& t : tmp.threats) out.threats.push_back(std::move(t));
    } else if (isOfficeExtension(ext)) {
        ScanResult tmp;
        HeuristicsEngine::addOfficeThreat(analyzeOfficeMacros(data.data(), data.size(), ext), tmp);
        for (auto& t : tmp.threats) out.threats.push_back(std::move(t));
    }

    out.ok = true;
    return out;
}

std::string contentAnalysisToJson(const ContentAnalysis& a) {
    nlohmann::json j;
    j["ok"] = a.ok;
    j["error"] = a.error;
    j["sha256"] = a.sha256;
    j["sha1"] = a.sha1;
    j["md5"] = a.md5;
    j["is_pe"] = a.isPE;
    j["pe_score"] = a.peScore;
    j["pe_reasons"] = a.peReasons;
    j["pe_packer"] = a.peDetectedPacker;
    j["threats"] = nlohmann::json::array();
    for (const auto& t : a.threats) {
        j["threats"].push_back({{"name", t.name}, {"method", t.method}, {"severity", t.severity},
                                {"score", t.score}, {"details", t.details}});
    }
    // ensure_ascii=true: salida 7-bit segura aunque los textos contengan bytes no UTF-8 válidos
    return j.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
}

bool contentAnalysisFromJson(const std::string& json, ContentAnalysis& out) {
    out = ContentAnalysis{};
    nlohmann::json j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) return false;

    try {
        out.ok = j.value("ok", false);
        out.error = j.value("error", std::string());
        out.sha256 = j.value("sha256", std::string());
        out.sha1 = j.value("sha1", std::string());
        out.md5 = j.value("md5", std::string());
        out.isPE = j.value("is_pe", false);
        out.peScore = std::clamp(j.value("pe_score", 0), 0, 100);
        out.peDetectedPacker = j.value("pe_packer", std::string());

        if (j.contains("pe_reasons") && j["pe_reasons"].is_array()) {
            for (const auto& r : j["pe_reasons"]) if (r.is_string()) out.peReasons.push_back(r.get<std::string>());
        }
        if (j.contains("threats") && j["threats"].is_array()) {
            for (const auto& t : j["threats"]) {
                if (!t.is_object()) continue;
                ThreatInfo ti;
                ti.name = t.value("name", std::string());
                ti.method = t.value("method", std::string());
                ti.severity = t.value("severity", std::string());
                ti.score = std::clamp(t.value("score", 0), 0, 100);
                ti.details = t.value("details", std::string());
                out.threats.push_back(std::move(ti));
            }
        }
    } catch (const std::exception&) {
        out = ContentAnalysis{};
        return false; // el trabajador es un proceso no confiable: cualquier formato inesperado se rechaza
    }
    return true;
}

} // namespace openguard
