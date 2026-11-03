# ==============================================================================
# OpenGuard GUI - Interfaz grafica nativa (Win32 + GDI)
# ==============================================================================

add_executable(openguard_gui WIN32
    main_gui.cpp
    openguard_gui.rc
)

target_link_libraries(openguard_gui PRIVATE
    openguard_core
    comctl32
    shell32
    ole32
    user32
    gdi32
    msimg32
)

# El manifiesto (Common Controls 6, administrador, DPI) va incrustado en el .rc
if(MSVC)
    target_link_options(openguard_gui PRIVATE /MANIFEST:NO)
endif()
