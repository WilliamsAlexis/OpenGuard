/**
 * @file yara_lite.cpp
 * @brief Implementación del intérprete de un subconjunto de reglas YARA.
 */

#include "openguard/yara_lite.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <regex>
#include <sstream>
#include <string_view>
#include <unordered_set>

namespace openguard {

namespace {

constexpr size_t kMaxScanBytes = 4 * 1024 * 1024;   // Máximo de bytes inspeccionados por archivo
constexpr size_t kMaxRegexBytes = 64 * 1024;        // Las regex solo se aplican al inicio del archivo (limita coste y recursión de std::regex)
constexpr size_t kMaxRegexPatternLen = 256;         // Patrones más largos se descartan al cargar

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string toLowerAscii(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool startsWith(const std::string& s, const char* prefix) {
    return s.rfind(prefix, 0) == 0;
}

// ----------------------------------------------------------------------------- modelo

struct StringDef {
    enum class Kind { Text, Hex, Regex } kind{Kind::Text};
    std::string id;                          // "$a"
    std::vector<std::string> patterns;       // Text: variantes ascii/wide (en minúsculas si nocase)
    std::vector<int> hexBytes;               // Hex: byte 0-255 o -1 = comodín
    std::shared_ptr<std::regex> re;          // Regex
    bool nocase{false};
    bool fullword{false};
};

struct Node {
    enum class Type { And, Or, Not, Var, Of, FileSize, Const } type{Type::Const};
    std::vector<Node> kids;
    std::vector<std::string> ids;            // Var: un id; Of: lista (puede tener prefijos "$a*")
    bool useThem{false};                     // Of ... them
    int required{1};                         // Of: N requerido; -1 = todos
    std::string op;                          // FileSize: comparador
    uint64_t value{0};                       // FileSize: valor; Const: 0/1
};

struct Rule {
    std::string name, severity{"medium"}, description, family;
    std::vector<StringDef> strings;
    Node condition;
};

// ----------------------------------------------------------------------------- preprocesado

/// Quita comentarios // y /* */ respetando cadenas entre comillas y líneas de regex.
std::string stripComments(const std::string& src) {
    std::string out;
    bool inBlock = false;
    std::istringstream in(src);
    std::string line;

    while (std::getline(in, line)) {
        const std::string t = trim(line);
        const bool regexLine = !inBlock && t.size() > 1 && t[0] == '$' &&
                               (t.find("= /") != std::string::npos || t.find("=/") != std::string::npos);
        std::string res;
        bool inStr = false;

        for (size_t i = 0; i < line.size(); ++i) {
            const char c = line[i];
            if (inBlock) {
                if (c == '*' && i + 1 < line.size() && line[i + 1] == '/') { inBlock = false; ++i; }
                continue;
            }
            if (regexLine) { res += c; continue; }
            if (inStr) {
                res += c;
                if (c == '\\' && i + 1 < line.size()) res += line[++i];
                else if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; res += c; continue; }
            if (c == '/' && i + 1 < line.size() && line[i + 1] == '/') break;
            if (c == '/' && i + 1 < line.size() && line[i + 1] == '*') { inBlock = true; ++i; continue; }
            res += c;
        }
        out += res;
        out += '\n';
    }
    return out;
}

/// Interpreta una cadena entre comillas desde s[pos]=='"'. Deja pos tras la comilla de cierre.
bool readQuoted(const std::string& s, size_t& pos, std::string& out) {
    if (pos >= s.size() || s[pos] != '"') return false;
    ++pos;
    out.clear();
    while (pos < s.size()) {
        const char c = s[pos++];
        if (c == '"') return true;
        if (c != '\\') { out += c; continue; }
        if (pos >= s.size()) return false;
        const char e = s[pos++];
        switch (e) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case '\\': out += '\\'; break;
            case '"': out += '"'; break;
            case 'x': {
                if (pos + 2 > s.size()) return false;
                const std::string hex = s.substr(pos, 2);
                if (hex.size() != 2 || !std::isxdigit(static_cast<unsigned char>(hex[0])) ||
                    !std::isxdigit(static_cast<unsigned char>(hex[1]))) return false;
                out += static_cast<char>(std::stoi(hex, nullptr, 16));
                pos += 2;
                break;
            }
            default: out += e; break;
        }
    }
    return false;
}

/// Procesa los modificadores restantes de una línea de string. @return false si hay uno no soportado.
bool parseModifiers(const std::string& rest, bool& nocase, bool& ascii, bool& wide, bool& fullword) {
    std::istringstream in(rest);
    std::string w;
    while (in >> w) {
        if (w == "nocase") nocase = true;
        else if (w == "ascii") ascii = true;
        else if (w == "wide") wide = true;
        else if (w == "fullword") fullword = true;
        else if (w == "private") continue;
        else return false; // xor, base64, etc.
    }
    return true;
}

bool parseStringLine(const std::string& line, StringDef& def) {
    const size_t eq = line.find('=');
    if (eq == std::string::npos) return false;
    def.id = trim(line.substr(0, eq));
    if (def.id.size() < 2 || def.id[0] != '$') return false;

    std::string value = trim(line.substr(eq + 1));
    bool nocase = false, ascii = false, wide = false, fullword = false;

    if (!value.empty() && value[0] == '"') {
        size_t pos = 0;
        std::string text;
        if (!readQuoted(value, pos, text) || text.empty()) return false;
        if (!parseModifiers(value.substr(pos), nocase, ascii, wide, fullword)) return false;

        def.kind = StringDef::Kind::Text;
        def.nocase = nocase;
        def.fullword = fullword;
        if (nocase) text = toLowerAscii(text);

        if (ascii || !wide) def.patterns.push_back(text);
        if (wide) {
            std::string w;
            for (char c : text) { w += c; w += '\0'; }
            def.patterns.push_back(w);
        }
        return true;
    }

    if (!value.empty() && value[0] == '{') {
        const size_t close = value.rfind('}');
        if (close == std::string::npos) return false;
        std::istringstream in(value.substr(1, close - 1));
        std::string tok;
        while (in >> tok) {
            if (tok == "??") { def.hexBytes.push_back(-1); continue; }
            if (tok.size() != 2 || !std::isxdigit(static_cast<unsigned char>(tok[0])) ||
                !std::isxdigit(static_cast<unsigned char>(tok[1]))) return false; // saltos [n-m], alternativas, etc.
            def.hexBytes.push_back(std::stoi(tok, nullptr, 16));
        }
        if (def.hexBytes.empty()) return false;
        def.kind = StringDef::Kind::Hex;
        return true;
    }

    if (!value.empty() && value[0] == '/') {
        const size_t close = value.rfind('/');
        if (close == 0) return false;
        const std::string pattern = value.substr(1, close - 1);
        if (pattern.empty() || pattern.size() > kMaxRegexPatternLen) return false;
        std::string mods = value.substr(close + 1);
        // Los flags 'i' y 's' pegados a la regex (ej: /abc/i) equivalen a nocase
        if (!mods.empty() && mods[0] != ' ') {
            const size_t sp = mods.find(' ');
            const std::string flags = mods.substr(0, sp);
            if (flags.find('i') != std::string::npos) nocase = true;
            mods = (sp == std::string::npos) ? "" : mods.substr(sp);
        }
        if (!parseModifiers(mods, nocase, ascii, wide, fullword) || wide) return false;
        try {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (nocase) flags |= std::regex::icase;
            def.re = std::make_shared<std::regex>(pattern, flags);
        } catch (const std::regex_error&) {
            return false;
        }
        def.kind = StringDef::Kind::Regex;
        def.nocase = nocase;
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------- condición

std::vector<std::string> tokenize(const std::string& s) {
    std::vector<std::string> toks;
    size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (std::isspace(static_cast<unsigned char>(c))) { ++i; continue; }
        if (c == '(' || c == ')' || c == ',') { toks.emplace_back(1, c); ++i; continue; }
        if (c == '$') {
            size_t j = i + 1;
            while (j < s.size() && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_' || s[j] == '*')) ++j;
            toks.push_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t j = i;
            while (j < s.size() && std::isalnum(static_cast<unsigned char>(s[j]))) ++j;
            toks.push_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t j = i;
            while (j < s.size() && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_' || s[j] == '.')) ++j;
            toks.push_back(s.substr(i, j - i));
            i = j;
            continue;
        }
        if (c == '<' || c == '>' || c == '=' || c == '!') {
            if (i + 1 < s.size() && s[i + 1] == '=') { toks.push_back(s.substr(i, 2)); i += 2; }
            else { toks.emplace_back(1, c); ++i; }
            continue;
        }
        toks.emplace_back("?"); // carácter no soportado (#, @, [, etc.)
        ++i;
    }
    return toks;
}

class CondParser {
public:
    explicit CondParser(std::vector<std::string> toks) : m_t(std::move(toks)) {}

    bool parse(Node& out) {
        out = parseOr();
        return !m_err && m_p == m_t.size();
    }

private:
    const std::string& peek() const { static const std::string kEnd; return m_p < m_t.size() ? m_t[m_p] : kEnd; }
    bool accept(const char* w) { if (peek() == w) { ++m_p; return true; } return false; }

    Node parseOr() {
        Node left = parseAnd();
        while (!m_err && peek() == "or") {
            ++m_p;
            Node n; n.type = Node::Type::Or;
            n.kids.push_back(std::move(left));
            n.kids.push_back(parseAnd());
            left = std::move(n);
        }
        return left;
    }
    Node parseAnd() {
        Node left = parseNot();
        while (!m_err && peek() == "and") {
            ++m_p;
            Node n; n.type = Node::Type::And;
            n.kids.push_back(std::move(left));
            n.kids.push_back(parseNot());
            left = std::move(n);
        }
        return left;
    }
    Node parseNot() {
        if (accept("not")) {
            Node n; n.type = Node::Type::Not;
            n.kids.push_back(parseNot());
            return n;
        }
        return parsePrimary();
    }

    static bool parseNumber(const std::string& tok, uint64_t& v) {
        size_t i = 0;
        while (i < tok.size() && std::isdigit(static_cast<unsigned char>(tok[i]))) ++i;
        if (i == 0) return false;
        try { v = std::stoull(tok.substr(0, i)); } catch (...) { return false; }
        const std::string suffix = tok.substr(i);
        if (suffix.empty()) return true;
        if (suffix == "KB") { v *= 1024ull; return true; }
        if (suffix == "MB") { v *= 1024ull * 1024ull; return true; }
        return false;
    }

    Node parsePrimary() {
        Node n;
        const std::string t = peek();
        if (t.empty()) { m_err = true; return n; }

        if (t == "(") {
            ++m_p;
            n = parseOr();
            if (!accept(")")) m_err = true;
            return n;
        }
        if (t == "true" || t == "false") {
            ++m_p;
            n.type = Node::Type::Const;
            n.value = (t == "true") ? 1 : 0;
            return n;
        }
        if (t == "filesize") {
            ++m_p;
            n.type = Node::Type::FileSize;
            n.op = peek();
            if (n.op != "<" && n.op != ">" && n.op != "<=" && n.op != ">=" && n.op != "==" && n.op != "!=") { m_err = true; return n; }
            ++m_p;
            if (!parseNumber(peek(), n.value)) { m_err = true; return n; }
            ++m_p;
            return n;
        }
        if (t[0] == '$') {
            ++m_p;
            n.type = Node::Type::Var;
            n.ids.push_back(t);
            return n;
        }
        // Cuantificador: N of ... | any of ... | all of ...
        uint64_t count = 0;
        int required = 1;
        if (t == "any") required = 1;
        else if (t == "all") required = -1;
        else if (parseNumber(t, count) && count > 0 && count < 1000) required = static_cast<int>(count);
        else { m_err = true; return n; }
        ++m_p;
        if (!accept("of")) { m_err = true; return n; }

        n.type = Node::Type::Of;
        n.required = required;
        if (accept("them")) { n.useThem = true; return n; }
        if (!accept("(")) { m_err = true; return n; }
        for (;;) {
            const std::string id = peek();
            if (id.empty() || id[0] != '$') { m_err = true; return n; }
            n.ids.push_back(id);
            ++m_p;
            if (accept(",")) continue;
            if (accept(")")) break;
            m_err = true;
            return n;
        }
        return n;
    }

    std::vector<std::string> m_t;
    size_t m_p{0};
    bool m_err{false};
};

struct EvalContext {
    const std::unordered_set<std::string>* matched;
    const std::vector<std::string>* allIds;
    uint64_t fileSize;
};

bool evaluate(const Node& n, const EvalContext& ctx) {
    switch (n.type) {
        case Node::Type::Const: return n.value != 0;
        case Node::Type::And:   return evaluate(n.kids[0], ctx) && evaluate(n.kids[1], ctx);
        case Node::Type::Or:    return evaluate(n.kids[0], ctx) || evaluate(n.kids[1], ctx);
        case Node::Type::Not:   return !evaluate(n.kids[0], ctx);
        case Node::Type::Var:   return ctx.matched->count(n.ids[0]) > 0;
        case Node::Type::FileSize: {
            const uint64_t f = ctx.fileSize;
            if (n.op == "<") return f < n.value;
            if (n.op == ">") return f > n.value;
            if (n.op == "<=") return f <= n.value;
            if (n.op == ">=") return f >= n.value;
            if (n.op == "==") return f == n.value;
            return f != n.value;
        }
        case Node::Type::Of: {
            std::vector<std::string> pool;
            if (n.useThem) {
                pool = *ctx.allIds;
            } else {
                for (const auto& id : n.ids) {
                    if (!id.empty() && id.back() == '*') {
                        const std::string prefix = id.substr(0, id.size() - 1);
                        for (const auto& all : *ctx.allIds) if (startsWith(all, prefix.c_str())) pool.push_back(all);
                    } else {
                        pool.push_back(id);
                    }
                }
            }
            if (pool.empty()) return false;
            size_t hits = 0;
            for (const auto& id : pool) hits += ctx.matched->count(id);
            return n.required < 0 ? hits == pool.size() : hits >= static_cast<size_t>(n.required);
        }
    }
    return false;
}

// ----------------------------------------------------------------------------- coincidencias

bool isWordChar(unsigned char c) { return std::isalnum(c) || c == '_'; }

bool findText(std::string_view hay, const std::string& pat, bool fullword) {
    size_t pos = 0;
    while ((pos = hay.find(pat, pos)) != std::string_view::npos) {
        if (!fullword) return true;
        const bool leftOk = pos == 0 || !isWordChar(static_cast<unsigned char>(hay[pos - 1]));
        const size_t end = pos + pat.size();
        const bool rightOk = end >= hay.size() || !isWordChar(static_cast<unsigned char>(hay[end]));
        if (leftOk && rightOk) return true;
        ++pos;
    }
    return false;
}

bool findHex(const uint8_t* data, size_t size, const std::vector<int>& pat) {
    if (pat.empty() || size < pat.size()) return false;
    const size_t last = size - pat.size();
    for (size_t i = 0; i <= last; ++i) {
        if (pat[0] >= 0) {
            const void* p = std::memchr(data + i, pat[0], last - i + 1);
            if (!p) return false;
            i = static_cast<size_t>(static_cast<const uint8_t*>(p) - data);
        }
        size_t k = 1;
        for (; k < pat.size(); ++k) {
            if (pat[k] >= 0 && data[i + k] != static_cast<uint8_t>(pat[k])) break;
        }
        if (k == pat.size()) return true;
    }
    return false;
}

} // namespace

// ----------------------------------------------------------------------------- Impl

struct YaraLite::Impl {
    std::vector<Rule> rules;
    size_t skipped{0};

    bool parseRule(const std::string& name, const std::vector<std::string>& body, bool isPrivate) {
        Rule rule;
        rule.name = name;
        if (isPrivate) return false;

        enum class Section { None, Meta, Strings, Condition } section = Section::None;
        std::string conditionText;

        for (const std::string& raw : body) {
            const std::string line = trim(raw);
            if (line.empty()) continue;
            if (line == "meta:") { section = Section::Meta; continue; }
            if (line == "strings:") { section = Section::Strings; continue; }
            if (startsWith(line, "condition:")) {
                section = Section::Condition;
                conditionText += line.substr(std::strlen("condition:")) + " ";
                continue;
            }

            switch (section) {
                case Section::Meta: {
                    const size_t eq = line.find('=');
                    if (eq == std::string::npos) break;
                    const std::string key = trim(line.substr(0, eq));
                    std::string val = trim(line.substr(eq + 1));
                    if (!val.empty() && val[0] == '"') {
                        size_t pos = 0;
                        std::string unq;
                        if (readQuoted(val, pos, unq)) val = unq;
                    }
                    if (key == "severity") rule.severity = toLowerAscii(val);
                    else if (key == "description") rule.description = val;
                    else if (key == "malware_family") rule.family = val;
                    break;
                }
                case Section::Strings: {
                    StringDef def;
                    if (!parseStringLine(line, def)) return false;
                    rule.strings.push_back(std::move(def));
                    break;
                }
                case Section::Condition:
                    conditionText += line + " ";
                    break;
                case Section::None:
                    return false;
            }
        }

        if (conditionText.empty()) return false;
        CondParser parser(tokenize(conditionText));
        if (!parser.parse(rule.condition)) return false;

        rules.push_back(std::move(rule));
        return true;
    }

    size_t parseSource(const std::string& source) {
        const std::string text = stripComments(source);
        std::istringstream in(text);
        std::string line;
        size_t loaded = 0;

        while (std::getline(in, line)) {
            std::string t = trim(line);
            bool isPrivate = false;
            if (startsWith(t, "private ")) { isPrivate = true; t = trim(t.substr(8)); }
            if (startsWith(t, "global ")) { t = trim(t.substr(7)); }
            if (!startsWith(t, "rule ")) continue; // import/include u otro texto: se ignora

            std::string name = trim(t.substr(5));
            const size_t stop = name.find_first_of(" \t{:");
            const bool braceOnLine = name.find('{') != std::string::npos;
            if (stop != std::string::npos) name = name.substr(0, stop);

            // Cuerpo hasta la línea que contiene solo '}'
            std::vector<std::string> body;
            if (!braceOnLine) {
                while (std::getline(in, line)) {          // buscar la '{' de apertura
                    if (line.find('{') != std::string::npos) break;
                }
            }
            while (std::getline(in, line)) {
                if (trim(line) == "}") break;
                body.push_back(line);
            }

            if (parseRule(name, body, isPrivate)) ++loaded;
            else ++skipped;
        }
        return loaded;
    }
};

YaraLite::YaraLite() : m_impl(std::make_unique<Impl>()) {}
YaraLite::~YaraLite() = default;
YaraLite::YaraLite(YaraLite&&) noexcept = default;
YaraLite& YaraLite::operator=(YaraLite&&) noexcept = default;

size_t YaraLite::loadFromString(const std::string& source) { return m_impl->parseSource(source); }

size_t YaraLite::loadFile(const std::filesystem::path& file) {
    std::ifstream in(file, std::ios::binary);
    if (!in.is_open()) return 0;
    std::ostringstream ss;
    ss << in.rdbuf();
    return m_impl->parseSource(ss.str());
}

size_t YaraLite::loadDirectory(const std::filesystem::path& dir) {
    size_t total = 0;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return 0;
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        if (!it->is_regular_file(e2)) continue;
        std::wstring ext = it->path().extension().wstring();
        if (ext == L".yar" || ext == L".yara") total += loadFile(it->path());
    }
    return total;
}

size_t YaraLite::ruleCount() const noexcept { return m_impl->rules.size(); }
size_t YaraLite::skippedCount() const noexcept { return m_impl->skipped; }

std::vector<YaraMatch> YaraLite::scan(const uint8_t* data, size_t size) const {
    std::vector<YaraMatch> matches;
    if (!data || size == 0 || m_impl->rules.empty()) {
        // Una regla puede ser "filesize == 0"; no es relevante: archivos vacíos no se analizan.
        return matches;
    }

    const size_t len = std::min(size, kMaxScanBytes);
    const std::string_view hay(reinterpret_cast<const char*>(data), len);
    std::string lowerCopy;
    bool lowerReady = false;
    auto lowered = [&]() -> std::string_view {
        if (!lowerReady) { lowerCopy = toLowerAscii(std::string(hay)); lowerReady = true; }
        return lowerCopy;
    };

    for (const Rule& rule : m_impl->rules) {
        std::unordered_set<std::string> matched;
        std::vector<std::string> allIds;
        allIds.reserve(rule.strings.size());

        for (const StringDef& s : rule.strings) {
            allIds.push_back(s.id);
            bool hit = false;
            switch (s.kind) {
                case StringDef::Kind::Text: {
                    const std::string_view h = s.nocase ? lowered() : hay;
                    for (const auto& p : s.patterns) {
                        if (findText(h, p, s.fullword)) { hit = true; break; }
                    }
                    break;
                }
                case StringDef::Kind::Hex:
                    hit = findHex(data, len, s.hexBytes);
                    break;
                case StringDef::Kind::Regex: {
                    const char* b = reinterpret_cast<const char*>(data);
                    try {
                        hit = std::regex_search(b, b + std::min(len, kMaxRegexBytes), *s.re);
                    } catch (const std::exception&) {
                        hit = false; // regex demasiado compleja para este contenido
                    }
                    break;
                }
            }
            if (hit) matched.insert(s.id);
        }

        const EvalContext ctx{&matched, &allIds, static_cast<uint64_t>(size)};
        if (evaluate(rule.condition, ctx)) {
            matches.push_back({rule.name, rule.severity, rule.description, rule.family});
        }
    }
    return matches;
}

} // namespace openguard
