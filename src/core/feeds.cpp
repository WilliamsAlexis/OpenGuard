/**
 * @file feeds.cpp
 * @brief Implementación de los importadores de fuentes y de la actualización verificada.
 */

#include "openguard/feeds.h"
#include "openguard/crypto_utils.h"
#include "openguard/net_update.h"
#include "openguard/paths.h"
#include "openguard/update_verify.h"
#include "openguard/yara_lite.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace openguard {

namespace {

namespace fs = std::filesystem;

std::string lowerStr(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool isHex(const std::string& s, size_t len) {
    return s.size() == len && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

/// Nombre de detección acotado y sin caracteres de control (los datos de una fuente externa no son de confianza).
std::string cleanName(const std::string& prefix, std::string name) {
    name.erase(std::remove_if(name.begin(), name.end(), [](unsigned char c) { return c < 32 || c == 127; }), name.end());
    const auto b = name.find_first_not_of(" \t");
    const auto e = name.find_last_not_of(" \t");
    name = (b == std::string::npos) ? std::string() : name.substr(b, e - b + 1);
    if (name.empty() || name == "n/a" || name == "null" || name == "None") name = "Unknown";
    if (name.size() > 80) name.resize(80);
    return prefix + name;
}

/// Divide una línea CSV respetando comillas dobles ("" dentro de un campo = comilla literal).
std::vector<std::string> splitCsv(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    bool inQuotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (inQuotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') { cur.push_back('"'); ++i; }
                else inQuotes = false;
            } else {
                cur.push_back(c);
            }
        } else if (c == '"') {
            inQuotes = true;
        } else if (c == ',') {
            fields.push_back(cur);
            cur.clear();
        } else if (c != ' ' || !cur.empty()) { // ignora espacios entre la coma y la comilla
            cur.push_back(c);
        }
    }
    fields.push_back(cur);
    return fields;
}

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : text) {
        if (c == '\n') { if (!cur.empty() && cur.back() == '\r') cur.pop_back(); lines.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!cur.empty()) lines.push_back(cur);
    return lines;
}

/// Importa registros en la base y devuelve cuántos eran nuevos.
void importRecords(SignatureDB& db, const std::vector<SignatureRecord>& records, FeedResult& res) {
    if (records.empty()) { res.ok = true; return; }
    size_t ins = 0, skp = 0;
    if (!db.bulkImport(records, ins, skp)) {
        res.error = "No se pudo escribir en la base de firmas (solo lectura o error de disco)";
        return;
    }
    res.inserted = ins;
    res.skipped += skp;
    res.ok = true;
}

bool validRuleFileName(const std::string& name) {
    if (name.size() < 5 || name.size() > 64) return false;
    if (name.substr(name.size() - 4) != ".yar") return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) { return std::isalnum(c) || c == '_' || c == '-' || c == '.'; }) &&
           name.find("..") == std::string::npos;
}

FeedResult updateOfficialHashes(SignatureDB& db, const FeedOptions& opt) {
    FeedResult res;
    res.feed = "official";

    std::string body, sig, err;
    if (!net::httpsGet(opt.officialBaseUrl + "/hashes_index.json", body, err, 32u * 1024u * 1024u)) { res.error = err; return res; }
    if (!net::httpsGet(opt.officialBaseUrl + "/hashes_index.json.sig", sig, err, 4096)) {
        res.error = "No se pudo obtener la firma del indice: " + err;
        return res;
    }
    if (!verifyOfficialSignature(body, sig)) {
        res.error = "La firma del indice de firmas NO es valida: se descarta (posible manipulacion)";
        return res;
    }
    res.signatureVerified = true;

    const fs::path tmp = paths::dataDir() / "download_official.json";
    { std::ofstream out(tmp, std::ios::binary); out << body; }
    size_t ins = 0, skp = 0;
    const bool ok = db.importFromJson(tmp, ins, skp);
    std::error_code ec;
    fs::remove(tmp, ec);
    if (!ok) { res.error = "El indice firmado no tiene un formato valido"; return res; }
    res.ok = true;
    res.inserted = ins;
    res.skipped = skp;
    return res;
}

FeedResult updateOfficialRules(const FeedOptions& opt) {
    FeedResult res;
    res.feed = "rules";

    std::string manifestText, sig, err;
    if (!net::httpsGet(opt.officialBaseUrl + "/rules_manifest.json", manifestText, err, 1024 * 1024)) { res.error = err; return res; }
    if (!net::httpsGet(opt.officialBaseUrl + "/rules_manifest.json.sig", sig, err, 4096)) {
        res.error = "No se pudo obtener la firma del manifiesto de reglas: " + err;
        return res;
    }
    if (!verifyOfficialSignature(manifestText, sig)) {
        res.error = "La firma del manifiesto de reglas NO es valida: se descarta (posible manipulacion)";
        return res;
    }
    res.signatureVerified = true;

    nlohmann::json manifest = nlohmann::json::parse(manifestText, nullptr, false);
    if (manifest.is_discarded() || !manifest.contains("files") || !manifest["files"].is_array()) {
        res.error = "Manifiesto de reglas invalido";
        return res;
    }

    const fs::path dir = opt.rulesDir.empty() ? (paths::dataDir() / "rules") : opt.rulesDir;
    std::error_code ec;
    fs::create_directories(dir, ec);

    std::vector<std::string> keep;
    for (const auto& entry : manifest["files"]) {
        if (!entry.is_object() || !entry.contains("name") || !entry["name"].is_string() ||
            !entry.contains("sha256") || !entry["sha256"].is_string()) continue;
        const std::string name = entry["name"].get<std::string>();
        const std::string expected = lowerStr(entry["sha256"].get<std::string>());
        if (!validRuleFileName(name) || !isHex(expected, 64)) { ++res.skipped; continue; }

        std::string rule;
        if (!net::httpsGet(opt.officialBaseUrl + "/yara_rules/" + name, rule, err, 1024 * 1024)) { ++res.skipped; continue; }
        if (CryptoUtils::computeSha256FromBuffer(rule.data(), rule.size()) != expected) { ++res.skipped; continue; } // contenido distinto al firmado

        YaraLite probe; // comprobación de cordura: debe contener reglas interpretables
        if (probe.loadFromString(rule) == 0) { ++res.skipped; continue; }

        const fs::path tmp = dir / (name + ".tmp");
        { std::ofstream out(tmp, std::ios::binary | std::ios::trunc); out << rule; }
        fs::rename(tmp, dir / name, ec); // reemplazo atómico
        if (ec) { fs::remove(tmp, ec); ++res.skipped; continue; }
        keep.push_back(name);
        ++res.inserted;
    }

    // Quitar reglas descargadas que el manifiesto ya no incluye
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string fname = paths::toUtf8(it->path().filename());
        if (validRuleFileName(fname) && std::find(keep.begin(), keep.end(), fname) == keep.end()) {
            std::error_code rec;
            fs::remove(it->path(), rec);
        }
    }
    res.ok = true;
    return res;
}

FeedResult updateBazaar(SignatureDB& db, const FeedOptions& opt, const SecretStore& secrets) {
    FeedResult res;
    res.feed = "bazaar";

    const auto key = secrets.get(kAbuseChSecret);
    if (!key || key->empty()) { res.error = "Falta la clave de abuse.ch (Configuracion > Fuentes de firmas)"; return res; }

    std::string body, err;
    if (!net::httpsGet(opt.bazaarUrl, body, err, 64u * 1024u * 1024u, *key)) { res.error = err; return res; }

    std::vector<SignatureRecord> records;
    const FeedStats stats = parseMalwareBazaarCsv(body, records);
    res.skipped = stats.skipped;
    if (records.empty()) { res.error = "La respuesta no contiene firmas validas (clave incorrecta o formato distinto)"; return res; }
    importRecords(db, records, res);
    return res;
}

} // namespace

FeedStats parseMalwareBazaarCsv(const std::string& text, std::vector<SignatureRecord>& out) {
    FeedStats st;
    for (const std::string& line : splitLines(text)) {
        if (line.empty() || line[0] == '#') continue;
        const auto f = splitCsv(line);
        // first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, ...
        if (f.size() < 4) { ++st.skipped; continue; }

        SignatureRecord r;
        r.sha256 = lowerStr(f[1]);
        r.md5 = lowerStr(f[2]);
        r.sha1 = lowerStr(f[3]);
        if (!isHex(r.sha256, 64)) { ++st.skipped; continue; }
        if (!r.md5.empty() && !isHex(r.md5, 32)) r.md5.clear();
        if (!r.sha1.empty() && !isHex(r.sha1, 40)) r.sha1.clear();

        r.malwareName = cleanName("MalwareBazaar.", f.size() > 8 ? f[8] : std::string());
        r.threatType = "malware";
        r.severity = "high";
        r.source = "malwarebazaar";
        out.push_back(std::move(r));
        ++st.parsed;
    }
    return st;
}

FeedStats parseClamAvHashDb(const std::string& text, std::vector<SignatureRecord>& out) {
    FeedStats st;
    for (const std::string& line : splitLines(text)) {
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string item;
        while (std::getline(ss, item, ':')) parts.push_back(item);
        if (parts.size() < 3) { ++st.skipped; continue; }

        SignatureRecord r;
        const std::string h = lowerStr(parts[0]);
        if (isHex(h, 64)) r.sha256 = h;
        else if (isHex(h, 40)) r.sha1 = h;
        else if (isHex(h, 32)) r.md5 = h;
        else { ++st.skipped; continue; }

        r.malwareName = cleanName("ClamAV.", parts[2]);
        r.threatType = "malware";
        r.severity = "high";
        r.source = "clamav";
        out.push_back(std::move(r));
        ++st.parsed;
    }
    return st;
}

std::vector<FeedResult> updateFeeds(SignatureDB& db, const FeedOptions& options, const SecretStore& secrets) {
    std::vector<FeedResult> results;
    if (options.official) results.push_back(updateOfficialHashes(db, options));
    if (options.rules) results.push_back(updateOfficialRules(options));
    if (options.bazaar) results.push_back(updateBazaar(db, options, secrets));
    return results;
}

} // namespace openguard
