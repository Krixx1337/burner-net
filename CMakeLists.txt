cmake_minimum_required(VERSION 3.21)

project(BurnerNet VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BURNERNET_BUILD_TESTING "Build BurnerNet offline/unit tests" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_BUILD_INTEGRATION_TESTS "Build BurnerNet live network integration tests" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_BUILD_EXAMPLES "Build BurnerNet examples" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_OBFUSCATE_STRINGS "Obfuscate BurnerNet security-anchor string literals" ON)
option(BURNERNET_HARDEN_IMPORTS "Resolve libcurl dynamically instead of linking it into the import table" OFF)

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
    find_library(BURNERNET_CRYPT32_LIBRARY NAMES crypt32)
    find_library(BURNERNET_WS2_32_LIBRARY NAMES ws2_32)
    if(NOT BURNERNET_BCRYPT_LIBRARY OR NOT BURNERNET_CRYPT32_LIBRARY OR NOT BURNERNET_WS2_32_LIBRARY)
        message(FATAL_ERROR
            "BurnerNet requires the Windows SDK libraries bcrypt, crypt32, and ws2_32, "
            "but one or more were not found during configuration.")
    endif()
endif()

set(BURNERNET_RUNTIME_DIR "${CMAKE_BINARY_DIR}/bin")

set(BURNERNET_SOURCES
    src/builder.cpp
    src/detail/memory_hygiene.cpp
    src/error.cpp
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
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(BurnerNet PUBLIC cxx_std_20)
set_target_properties(BurnerNet PROPERTIES
    CXX_EXTENSIONS OFF
)

target_compile_definitions(BurnerNet
    PUBLIC
        BURNER_ENABLE_CURL=1
        BURNERNET_OBFUSCATE_STRINGS=$<IF:$<BOOL:${BURNERNET_OBFUSCATE_STRINGS}>,1,0>
        BURNERNET_HARDEN_IMPORTS=$<IF:$<BOOL:${BURNERNET_HARDEN_IMPORTS}>,1,0>
    PRIVATE
        BURNER_BUILDING_LIBRARY
        HOSTILE_CORE_EXPORT=BURNER_API
)

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
            ${BURNERNET_CRYPT32_LIBRARY}
            ${BURNERNET_WS2_32_LIBRARY}
    )
endif()

function(burnernet_configure_runtime target_name)
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${BURNERNET_RUNTIME_DIR}"
    )

    if(WIN32 AND NOT (DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "static"))
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:${target_name}>/redist"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:${target_name}>
                "$<TARGET_FILE_DIR:${target_name}>"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_RUNTIME_DLLS:${target_name}>
                "$<TARGET_FILE_DIR:${target_name}>/redist"
            COMMAND ${CMAKE_COMMAND}
                -DBURNER_SOURCE_DIR="$<TARGET_FILE_DIR:${target_name}>"
                -DBURNER_REDIST_DIR="$<TARGET_FILE_DIR:${target_name}>/redist"
                -P "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/cmake/SyncRedist.cmake"
            COMMAND_EXPAND_LISTS
        )
    endif()
endfunction()

function(burner_configure_runtime target_name)
    burnernet_configure_runtime(${target_name})
endfunction()

function(burner_apply_example_warnings target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

if(BURNERNET_BUILD_EXAMPLES)
    add_executable(BurnerNetExampleBasic examples/01_basic_usage.cpp)
    target_link_libraries(BurnerNetExampleBasic PRIVATE BurnerNet)
    burner_apply_example_warnings(BurnerNetExampleBasic)
    burnernet_configure_runtime(BurnerNetExampleBasic)

    add_executable(BurnerNetExampleAudit examples/02_security_audit.cpp)
    target_link_libraries(BurnerNetExampleAudit PRIVATE BurnerNet)
    burner_apply_example_warnings(BurnerNetExampleAudit)
    burnernet_configure_runtime(BurnerNetExampleAudit)

    add_executable(BurnerNetExampleTrafficLanes examples/03_traffic_lanes.cpp)
    target_link_libraries(BurnerNetExampleTrafficLanes PRIVATE BurnerNet)
    burner_apply_example_warnings(BurnerNetExampleTrafficLanes)
    burnernet_configure_runtime(BurnerNetExampleTrafficLanes)

    add_executable(BurnerNetExampleCustomPolicy examples/04_custom_security_policy.cpp)
    target_link_libraries(BurnerNetExampleCustomPolicy PRIVATE BurnerNet)
    burner_apply_example_warnings(BurnerNetExampleCustomPolicy)
    burnernet_configure_runtime(BurnerNetExampleCustomPolicy)
endif()

if(BURNERNET_BUILD_TESTING OR BURNERNET_BUILD_INTEGRATION_TESTS)
    enable_testing()
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
    burnernet_configure_runtime(BurnerNetTests)
    add_test(NAME BurnerNet.Unit COMMAND BurnerNetTests)
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
    burnernet_configure_runtime(BurnerNetIntegrationTests)
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
