# ==============================================================================
# OpenGuard Worker - proceso aislado que analiza contenido no confiable
# ==============================================================================

add_executable(openguard_worker
    main_worker.cpp
)

target_link_libraries(openguard_worker PRIVATE
    openguard_core
)
