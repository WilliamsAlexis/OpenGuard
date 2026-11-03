# ==============================================================================
# OpenGuard GUI - Interfaz grafica nativa (Win32)
# ==============================================================================

add_executable(openguard_gui WIN32
    main_gui.cpp
)

target_link_libraries(openguard_gui PRIVATE
    openguard_core
    comctl32
    shell32
    ole32
    user32
    gdi32
)
