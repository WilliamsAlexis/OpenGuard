/**
 * @file updater.cpp
 * @brief Implementación de la actualización de firmas en línea.
 */

#include "openguard/updater.h"
#include "openguard/net_update.h"
#include "openguard/paths.h"

#include <filesystem>
#include <fstream>

namespace openguard {

UpdateResult updateSignaturesOnline(SignatureDB& db, const std::string& url,
                                    const std::string& authKey, const std::string& listName) {
    UpdateResult res;

    if (!db.isOpen() || db.isReadOnly()) {
        res.error = "La base de firmas es de solo lectura: ejecute OpenGuard como Administrador.";
        return res;
    }

    std::string body;
    if (!net::httpsGet(url, body, res.error, 64u * 1024u * 1024u, authKey)) return res;

    // Saltar BOM UTF-8 y espacios para detectar si es JSON
    size_t first = 0;
    if (body.size() >= 3 && static_cast<unsigned char>(body[0]) == 0xEF &&
        static_cast<unsigned char>(body[1]) == 0xBB && static_cast<unsigned char>(body[2]) == 0xBF) first = 3;
    first = body.find_first_not_of(" \t\r\n", first);
    const bool isJson = first != std::string::npos && body[first] == '{';

    bool ok = false;
    if (isJson) {
        const std::filesystem::path tmp = paths::dataDir() / "download.json";
        {
            std::ofstream out(tmp, std::ios::binary);
            out << body;
        }
        ok = db.importFromJson(tmp, res.inserted, res.skipped);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
    } else {
        ok = db.importHashList(body, listName, "online", res.inserted, res.skipped);
    }

    if (!ok) res.error = "El contenido descargado no tiene un formato valido.";
    res.ok = ok;
    return res;
}

} // namespace openguard
