# ==============================================================================
# OpenGuard - Antivirus Defensivo para Windows 10/11
# Archivo de Configuración de CMake Principal
# Estándar: C++20 | Compilador: MSVC (Visual Studio 2022)
# ==============================================================================

cmake_minimum_required(VERSION 3.22)

# Nombre del proyecto y metadatos de versión
project(OpenGuard
    VERSION 0.1.0
    DESCRIPTION "Antivirus gratuito y de código abierto para Windows en C++20"
    LANGUAGES C CXX
)

# Requerir estrictamente estándar C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Opciones de compilación
option(BUILD_TESTING "Compilar la suite de pruebas unitarias" ON)
option(BUILD_CLI "Compilar la herramienta de consola openguard_cli" ON)
option(BUILD_SERVICE "Compilar el servicio de Windows openguard_service" ON)

# Configuración específica para el compilador MSVC en Windows
if(MSVC)
    add_compile_options(
        /W4                 # Nivel de advertencias 4 (alto)
        /permissive-        # Cumplimiento estricto del estándar C++
        /utf-8              # Codificación UTF-8 para código fuente y ejecución
        /EHsc               # Manejo estándar de excepciones C++
        /volatile:iso       # Semántica ISO para variables volátiles
        /Zc:__cplusplus     # Reportar la macro __cplusplus correcta
        /guard:cf           # Control Flow Guard para mitigación de exploits
    )
    add_link_options(
        /DYNAMICBASE        # Habilitar ASLR (Address Space Layout Randomization)
        /NXCOMPAT           # Habilitar DEP (Data Execution Prevention)
        /GUARD:CF           # Control Flow Guard enlazado
    )
    # Definición de macros seguras de Windows y soporte Unicode completo
    add_compile_definitions(
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# Directorio global de encabezados públicos
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Búsqueda de dependencias mediante CMake / vcpkg
find_package(sqlite3 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG QUIET)

# Biblioteca central: openguard_core
add_subdirectory(src/core)

# Aplicación CLI: openguard_cli
if(BUILD_CLI)
    add_subdirectory(src/cli)
endif()

# Servicio de Windows: openguard_service
if(BUILD_SERVICE)
    add_subdirectory(src/service)
endif()

# Suite de pruebas unitarias (Google Test)
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest CONFIG QUIET)
    if(GTest_FOUND)
        add_subdirectory(tests)
    else()
        message(STATUS "Google Test no encontrado en vcpkg. Pruebas deshabilitadas temporalmente.")
    endif()
endif()

