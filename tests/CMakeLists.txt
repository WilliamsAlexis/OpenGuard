# ==============================================================================
# OpenGuard - Suite de Pruebas Unitarias (Google Test en C++20)
# ==============================================================================

add_executable(openguard_tests
    test_signatures.cpp
    test_scanner.cpp
    test_quarantine.cpp
    test_heuristics.cpp
    test_extra_core.cpp
    test_realtime_pe.cpp
    test_yara.cpp
    test_update.cpp
)

target_compile_definitions(openguard_tests PRIVATE
    OPENGUARD_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(openguard_tests PRIVATE
    openguard_core
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME OpenGuardUnitTests COMMAND openguard_tests)
