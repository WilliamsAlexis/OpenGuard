# ==============================================================================
# OpenGuard - Antivirus Defensivo para Windows 10/11
# Archivo de Configuración de CMake Principal
# Estándar: C++20 | Compilador: MSVC (Visual Studio 2022)
# ==============================================================================

cmake_minimum_required(VERSION 3.22)

# Nombre del proyecto y metadatos de versión
project(OpenGuard
    VERSION 0.4.0
    DESCRIPTION "Antivirus gratuito y de código abierto para Windows en C++20"
    LANGUAGES C CXX
)

# Requerir estrictamente estándar C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Recursos de Windows (icono y manifiesto de la GUI)
if(WIN32)
    enable_language(RC)
endif()

# Opciones de compilación
option(BUILD_TESTING "Compilar la suite de pruebas unitarias" ON)
option(BUILD_CLI "Compilar la herramienta de consola openguard_cli" ON)
option(BUILD_SERVICE "Compilar el servicio de Windows openguard_service" ON)
option(BUILD_GUI "Compilar la interfaz grafica openguard_gui" ON)
option(OPENGUARD_STATIC_RUNTIME
       "Enlazar el runtime de C++ de forma estática (/MT) para no requerir el VC++ Redistributable. \
Exige un triplet estático de vcpkg (x64-windows-static)." ON)

# Configuración específica para el compilador MSVC en Windows
if(MSVC)
    if(OPENGUARD_STATIC_RUNTIME)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()

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
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# Macros de Windows (válidas para cualquier compilador)
add_compile_definitions(
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    OPENGUARD_VERSION="${PROJECT_VERSION}"
)

# Directorio global de encabezados públicos
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Búsqueda de dependencias mediante CMake / vcpkg
find_package(unofficial-sqlite3 CONFIG QUIET)
if(NOT TARGET unofficial::sqlite3::sqlite3)
    find_package(SQLite3 REQUIRED)
endif()
find_package(nlohmann_json CONFIG REQUIRED)

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

# Proceso trabajador aislado (lo usa el servicio para analizar contenido no confiable)
add_subdirectory(src/worker)

# Interfaz grafica: openguard_gui
if(BUILD_GUI)
    add_subdirectory(src/gui)
endif()

# Suite de pruebas unitarias (Google Test)
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest CONFIG QUIET)
    if(NOT TARGET GTest::gtest)
        find_package(GTest QUIET)
    endif()
    if(TARGET GTest::gtest)
        add_subdirectory(tests)
    else()
        message(STATUS "Google Test no encontrado. Pruebas unitarias omitidas en esta fase.")
    endif()
endif()
