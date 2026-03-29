cmake_minimum_required(VERSION 3.21)

project(BurnerNet VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/burner/net/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include/burner/net/version.h
    @ONLY
)

option(BURNERNET_BUILD_TESTING "Build BurnerNet offline/unit tests" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_BUILD_INTEGRATION_TESTS "Build BurnerNet live network integration tests" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_BUILD_EXAMPLES "Build BurnerNet examples" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_OBFUSCATE_STRINGS "Obfuscate BurnerNet security-anchor string literals" ON)
option(BURNERNET_HARDEN_ERRORS "Emit numeric error codes instead of symbolic strings" OFF)
option(BURNERNET_HARDEN_IMPORTS "Resolve libcurl dynamically instead of linking it into the import table" OFF)

if(BURNERNET_OBFUSCATE_STRINGS)
    set(BURNERNET_OBFUSCATE_STRINGS_VALUE 1)
else()
    set(BURNERNET_OBFUSCATE_STRINGS_VALUE 0)
endif()

set(BURNERNET_CUSTOM_OBFUSCATOR_HEADER "" CACHE STRING "Optional custom obfuscator header token, for example my_obfuscator.h or <my/obfuscator.hpp>")
set(BURNERNET_CUSTOM_OBFUSCATOR_INCLUDE_DIR "" CACHE PATH "Optional include directory for the custom obfuscator header during build-tree usage")
set(BURNERNET_USER_CONFIG_HEADER "" CACHE STRING "Path to the project-specific BurnerNet config header")
set(BURNERNET_USER_CONFIG_INCLUDE_DIR "" CACHE PATH "Optional include directory for the project-specific BurnerNet config header during build-tree usage")

if((BURNERNET_BUILD_TESTING OR BURNERNET_BUILD_INTEGRATION_TESTS) AND NOT BURNERNET_USER_CONFIG_HEADER)
    set(BURNERNET_USER_CONFIG_HEADER "BurnerNet_TestConfig.h")
    set(BURNERNET_USER_CONFIG_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
endif()

if(BURNERNET_CUSTOM_OBFUSCATOR_HEADER)
    set(BURNERNET_HAS_CUSTOM_OBFUSCATOR 1)
    if(BURNERNET_CUSTOM_OBFUSCATOR_HEADER MATCHES "^[<\"].*[>\"]$")
        set(BURNERNET_CUSTOM_OBFUSCATOR_HEADER_LITERAL "${BURNERNET_CUSTOM_OBFUSCATOR_HEADER}")
    else()
        set(BURNERNET_CUSTOM_OBFUSCATOR_HEADER_LITERAL "\"${BURNERNET_CUSTOM_OBFUSCATOR_HEADER}\"")
    endif()
else()
    set(BURNERNET_HAS_CUSTOM_OBFUSCATOR 0)
endif()

if(BURNERNET_USER_CONFIG_HEADER)
    if(BURNERNET_USER_CONFIG_HEADER MATCHES "^[<\"].*[>\"]$")
        set(BURNERNET_USER_CONFIG_HEADER_LITERAL "${BURNERNET_USER_CONFIG_HEADER}")
    else()
        set(BURNERNET_USER_CONFIG_HEADER_LITERAL "\"${BURNERNET_USER_CONFIG_HEADER}\"")
    endif()
endif()

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/burner/net/obfuscation_config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include/burner/net/obfuscation_config.h
    @ONLY
)

include(CTest)

if(DEFINED CMAKE_CXX_STANDARD AND CMAKE_CXX_STANDARD LESS 20)
    message(FATAL_ERROR "BurnerNet requires C++20 or newer. Set CMAKE_CXX_STANDARD to 20 or higher before adding this project.")
endif()

find_package(CURL REQUIRED)
if(BURNERNET_BUILD_TESTING OR BURNERNET_BUILD_INTEGRATION_TESTS)
    find_package(doctest CONFIG REQUIRED)
endif()

if(WIN32)
    find_library(BURNERNET_BCRYPT_LIBRARY NAMES bcrypt)
    if(NOT BURNERNET_BCRYPT_LIBRARY)
        message(FATAL_ERROR "BurnerNet requires the Windows BCrypt library, but it was not found during configuration.")
    endif()
endif()

set(BURNERNET_RUNTIME_DIR "${CMAKE_BINARY_DIR}/bin")

set(BURNERNET_SOURCES
    src/builder.cpp
    src/curl/curl_http_client.cpp
    src/http_factory.cpp
    src/internal/header_validation.cpp
    src/internal/import_pointer_trust.cpp
    src/security/security_auditor.cpp
    src/security/signature_verifier.cpp
)

if(WIN32)
    list(APPEND BURNERNET_SOURCES src/bootstrap/bootstrap_windows.cpp)
endif()

add_library(BurnerNet ${BURNERNET_SOURCES})
add_library(BurnerNet::BurnerNet ALIAS BurnerNet)

target_include_directories(BurnerNet
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(BURNERNET_CUSTOM_OBFUSCATOR_INCLUDE_DIR)
    target_include_directories(BurnerNet
        PUBLIC
            $<BUILD_INTERFACE:${BURNERNET_CUSTOM_OBFUSCATOR_INCLUDE_DIR}>
    )
endif()

if(BURNERNET_USER_CONFIG_INCLUDE_DIR)
    target_include_directories(BurnerNet
        PUBLIC
            $<BUILD_INTERFACE:${BURNERNET_USER_CONFIG_INCLUDE_DIR}>
    )
endif()

target_compile_features(BurnerNet PUBLIC cxx_std_20)
set_target_properties(BurnerNet PROPERTIES
    CXX_EXTENSIONS OFF
)

target_compile_definitions(BurnerNet
    PUBLIC
        BURNER_ENABLE_CURL=1
        BURNERNET_HARDEN_IMPORTS=$<IF:$<BOOL:${BURNERNET_HARDEN_IMPORTS}>,1,0>
        BURNERNET_HARDEN_ERRORS=$<IF:$<BOOL:${BURNERNET_HARDEN_ERRORS}>,1,0>
    PRIVATE
        BURNER_BUILDING_LIBRARY
)

if(NOT "${BURNERNET_USER_CONFIG_HEADER}" STREQUAL "")
    target_compile_definitions(BurnerNet PUBLIC
        BURNERNET_USER_CONFIG_HEADER=${BURNERNET_USER_CONFIG_HEADER_LITERAL}
    )
endif()

if(BUILD_SHARED_LIBS)
    target_compile_definitions(BurnerNet PUBLIC BURNER_SHARED)
endif()

if(DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "static")
    target_compile_definitions(BurnerNet PUBLIC CURL_STATICLIB)
endif()

if(MSVC)
    target_compile_options(BurnerNet PRIVATE /W4 /WX /permissive-)
else()
    target_compile_options(BurnerNet PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(BURNERNET_HARDEN_IMPORTS)
    get_target_property(BURNERNET_CURL_INCLUDE_DIRS CURL::libcurl INTERFACE_INCLUDE_DIRECTORIES)
    if(BURNERNET_CURL_INCLUDE_DIRS)
        target_include_directories(BurnerNet PUBLIC ${BURNERNET_CURL_INCLUDE_DIRS})
    endif()
    target_compile_definitions(BurnerNet PRIVATE CURL_STATICLIB)
else()
    target_link_libraries(BurnerNet
        PUBLIC
            CURL::libcurl
    )
endif()

if(WIN32)
    target_link_libraries(BurnerNet
        PUBLIC
            ${BURNERNET_BCRYPT_LIBRARY}
            crypt32
            ws2_32
    )
endif()

function(burner_configure_runtime target_name)
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${BURNERNET_RUNTIME_DIR}"
    )

    if(WIN32 AND NOT (DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "static"))
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:${target_name}>/redist"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:${target_name}>
                "$<TARGET_FILE_DIR:${target_name}>/redist"
            COMMAND ${CMAKE_COMMAND}
                -DBURNER_SOURCE_DIR="$<TARGET_FILE_DIR:${target_name}>"
                -DBURNER_REDIST_DIR="$<TARGET_FILE_DIR:${target_name}>/redist"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SyncRedist.cmake"
            COMMAND_EXPAND_LISTS
        )
    endif()
endfunction()

if(BURNERNET_BUILD_EXAMPLES)
    add_executable(BurnerNetExampleBasic examples/01_basic_usage.cpp)
    target_link_libraries(BurnerNetExampleBasic PRIVATE BurnerNet)
    if(MSVC)
        target_compile_options(BurnerNetExampleBasic PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(BurnerNetExampleBasic PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burner_configure_runtime(BurnerNetExampleBasic)

    add_executable(BurnerNetExampleAudit examples/02_security_audit.cpp)
    target_link_libraries(BurnerNetExampleAudit PRIVATE BurnerNet)
    if(MSVC)
        target_compile_options(BurnerNetExampleAudit PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(BurnerNetExampleAudit PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burner_configure_runtime(BurnerNetExampleAudit)

    add_executable(BurnerNetExampleTrafficLanes examples/03_traffic_lanes.cpp)
    target_link_libraries(BurnerNetExampleTrafficLanes PRIVATE BurnerNet)
    if(MSVC)
        target_compile_options(BurnerNetExampleTrafficLanes PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(BurnerNetExampleTrafficLanes PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burner_configure_runtime(BurnerNetExampleTrafficLanes)
endif()

if(BURNERNET_BUILD_TESTING OR BURNERNET_BUILD_INTEGRATION_TESTS)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter QUIET)
endif()

if(BURNERNET_BUILD_TESTING)
    add_executable(BurnerNetTests
        tests/test_main.cpp
        tests/unit_tests.cpp
    )
    target_include_directories(BurnerNetTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(BurnerNetTests PRIVATE BurnerNet doctest::doctest)
    if(MSVC)
        target_compile_options(BurnerNetTests PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(BurnerNetTests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burner_configure_runtime(BurnerNetTests)
    add_test(NAME BurnerNet.Unit COMMAND BurnerNetTests)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME BurnerNet.GeneratorPolymorphism
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_burner_generator.py
        )
    endif()
endif()

if(BURNERNET_BUILD_INTEGRATION_TESTS)
    add_executable(BurnerNetIntegrationTests
        tests/test_main.cpp
        tests/integration_tests.cpp
    )
    target_include_directories(BurnerNetIntegrationTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(BurnerNetIntegrationTests PRIVATE BurnerNet doctest::doctest)
    if(MSVC)
        target_compile_options(BurnerNetIntegrationTests PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(BurnerNetIntegrationTests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burner_configure_runtime(BurnerNetIntegrationTests)
    add_test(NAME BurnerNet.Integration COMMAND BurnerNetIntegrationTests)

    add_custom_target(run_integration_tests
        COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG> --output-on-failure -R BurnerNet.Integration
        DEPENDS BurnerNetIntegrationTests
        USES_TERMINAL
        COMMENT "Run BurnerNet integration tests"
    )
endif()

set(BURNERNET_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/BurnerNet")

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/BurnerNetConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/BurnerNetConfig.cmake
    INSTALL_DESTINATION ${BURNERNET_INSTALL_CMAKEDIR}
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/BurnerNetConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(TARGETS BurnerNet
    EXPORT BurnerNetTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/burner DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/include/burner DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT BurnerNetTargets
    FILE BurnerNetTargets.cmake
    NAMESPACE BurnerNet::
    DESTINATION ${BURNERNET_INSTALL_CMAKEDIR}
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/BurnerNetConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/BurnerNetConfigVersion.cmake
    DESTINATION ${BURNERNET_INSTALL_CMAKEDIR}
)
