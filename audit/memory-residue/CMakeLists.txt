cmake_minimum_required(VERSION 3.21)

project(BurnerNetMemoryAudit LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "BurnerNetMemoryAudit requires Windows x64.")
endif()
if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "BurnerNetMemoryAudit requires CMAKE_BUILD_TYPE=Release.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST
    "Enable Maximum Ghost allocator hooks in this audit build"
    ON)

set(BURNERNET_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH
    "Path to the local BurnerNet source checkout")
if(NOT EXISTS "${BURNERNET_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "BURNERNET_SOURCE_DIR does not point to a BurnerNet checkout: "
        "${BURNERNET_SOURCE_DIR}")
endif()

set(BURNERNET_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BURNERNET_BUILD_INTEGRATION_TESTS OFF CACHE BOOL "" FORCE)
set(BURNERNET_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BURNERNET_HARDEN_IMPORTS ON CACHE BOOL "" FORCE)
set(BURNERNET_DIAGNOSTIC_STRINGS OFF CACHE BOOL "" FORCE)
set(BURNERNET_OBFUSCATE_STRINGS ON CACHE BOOL "" FORCE)
set(BURNERNET_MAXIMUM_GHOST ${BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST}
    CACHE BOOL "" FORCE)
set(BURNERNET_RUNTIME_DIR "${CMAKE_BINARY_DIR}/bin")

add_subdirectory(
    "${BURNERNET_SOURCE_DIR}"
    "${CMAKE_CURRENT_BINARY_DIR}/_deps/burner-net"
)

add_executable(BurnerNetMemoryAudit memory_audit.cpp)
target_link_libraries(BurnerNetMemoryAudit PRIVATE BurnerNet::BurnerNet)
target_compile_definitions(BurnerNetMemoryAudit PRIVATE
    BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST=$<IF:$<BOOL:${BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST}>,1,0>
)
if(MSVC)
    target_compile_options(BurnerNetMemoryAudit PRIVATE /W4 /permissive- /EHsc /GR-)
else()
    target_compile_options(BurnerNetMemoryAudit PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti)
endif()

burnernet_configure_runtime(BurnerNetMemoryAudit)
