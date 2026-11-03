# ==============================================================================
# OpenGuard - Suite de Pruebas Unitarias (Google Test en C++20)
# ==============================================================================

add_executable(openguard_tests
    test_signatures.cpp
    test_scanner.cpp
    test_quarantine.cpp
    test_heuristics.cpp
)

target_link_libraries(openguard_tests PRIVATE
    openguard_core
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME OpenGuardUnitTests COMMAND openguard_tests)
