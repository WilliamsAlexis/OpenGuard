# ==============================================================================
# OpenGuard CLI - Herramienta de Consola
# ==============================================================================

add_executable(openguard_cli
    main_cli.cpp
)

target_link_libraries(openguard_cli PRIVATE
    openguard_core
)

