/**
 * @file secrets.h
 * @brief Almacén de secretos (claves de API) cifrados con DPAPI; nunca en texto plano ni en el código.
 * @details Cada secreto se guarda en %ProgramData%\OpenGuard\secrets\<nombre>.bin protegido con DPAPI a nivel de
 *          equipo, de modo que lo puedan leer tanto el servicio (SYSTEM) como la aplicación (administrador).
 *          Limitación: cualquier proceso con privilegios de administrador en este equipo puede descifrarlos;
 *          DPAPI protege los archivos en reposo (discos copiados, copias de seguridad), no contra administradores.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace openguard {

class SecretStore {
public:
    /// @param directory Carpeta de secretos; vacía = %ProgramData%\OpenGuard\secrets.
    explicit SecretStore(std::filesystem::path directory = {});

    /// Guarda (o reemplaza) un secreto. @return false si el nombre es inválido o no se pudo cifrar/escribir.
    bool set(const std::string& name, const std::string& value);

    /// Recupera un secreto descifrado, o nullopt si no existe o no se puede descifrar.
    [[nodiscard]] std::optional<std::string> get(const std::string& name) const;

    /// Elimina un secreto. @return true si ya no existe.
    bool remove(const std::string& name);

    [[nodiscard]] bool has(const std::string& name) const;

private:
    [[nodiscard]] std::filesystem::path fileFor(const std::string& name) const;
    std::filesystem::path m_dir;
};

} // namespace openguard
