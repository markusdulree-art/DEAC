cmake_minimum_required(VERSION 3.23)
project(DEAC LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(deac_common INTERFACE)
target_include_directories(deac_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/common/include)

if (WIN32)
    find_package(nlohmann_json CONFIG REQUIRED)

    add_executable(deac_service
        service/src/main.cpp
        service/src/driver_client.cpp
        service/src/service_runtime.cpp
        service/src/telemetry_engine.cpp
        service/src/deac_detection.cpp
        service/src/deac_policy.cpp
        service/src/evidence_store.cpp
        service/src/privacy.cpp
        service/src/update_manager.cpp
        service/src/gsi_adapter.cpp
        service/src/deac_config.cpp
        service/src/audit_log.cpp
        service/src/module_inventory.cpp
    )
    target_include_directories(deac_service PRIVATE service/include common/include)
    target_link_libraries(deac_service PRIVATE deac_common advapi32 bcrypt wintrust crypt32 psapi nlohmann_json::nlohmann_json)
    target_compile_definitions(deac_service PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)

    add_executable(deac_installer
        installer/src/main.cpp
        installer/src/system_requirements.cpp
        installer/src/service_install.cpp
    )
    target_include_directories(deac_installer PRIVATE installer/include)
    target_link_libraries(deac_installer PRIVATE advapi32)
    target_compile_definitions(deac_installer PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

enable_testing()
add_executable(deac_tests
    tests/test_detection.cpp
    service/src/telemetry_engine.cpp
    service/src/deac_detection.cpp
    service/src/deac_policy.cpp
    service/src/deac_config.cpp
)
target_include_directories(deac_tests PRIVATE service/include common/include)
add_test(NAME deac_tests COMMAND deac_tests)

# Kernel driver is built using the WDK/MSBuild driver toolchain.
