# ==============================================================================
# OpenGuard Core - Biblioteca Central del Motor Antivirus (C++20)
# ==============================================================================

add_library(openguard_core STATIC
    crypto_utils.cpp
    signatures.cpp
    thread_pool.cpp
    scanner.cpp
    pe_analyzer.cpp
    quarantine.cpp
    heuristics.cpp
    vuln_scan.cpp
    network_scan.cpp
)

target_include_directories(openguard_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Enlace con librerías nativas de Windows y dependencias de terceros
target_link_libraries(openguard_core PUBLIC
    bcrypt          # Windows CNG Cryptography API (SHA-256, AES-256)
    wintrust        # Verificación de firmas digitales Authenticode
    crypt32         # Certificados digitales y parseo X.509
    iphlpapi        # IP Helper API para conexiones TCP/UDP y adaptadores
    ws2_32          # Windows Sockets (Winsock)
    netapi32        # Gestión de usuarios y cuentas de red
)

# Enlace flexible de SQLite3 según proveedor (vcpkg config o FindSQLite3)
if(TARGET unofficial::sqlite3::sqlite3)
    target_link_libraries(openguard_core PUBLIC unofficial::sqlite3::sqlite3)
elseif(TARGET SQLite::SQLite3)
    target_link_libraries(openguard_core PUBLIC SQLite::SQLite3)
else()
    target_link_libraries(openguard_core PUBLIC sqlite3)
endif()

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(openguard_core PUBLIC nlohmann_json::nlohmann_json)
endif()
