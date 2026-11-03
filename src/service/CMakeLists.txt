# ==============================================================================
# OpenGuard Service - Servicio de Monitoreo de Windows
# ==============================================================================

add_executable(openguard_service
    service_main.cpp
)

target_link_libraries(openguard_service PRIVATE
    openguard_core
    advapi32
)

