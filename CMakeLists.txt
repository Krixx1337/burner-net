cmake_minimum_required(VERSION 3.21)

project(BurnerNet VERSION 0.1.0 LANGUAGES CXX)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BURNERNET_BUILD_TESTING "Build BurnerNet offline/unit tests" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_BUILD_INTEGRATION_TESTS "Build BurnerNet live network integration tests" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_BUILD_EXAMPLES "Build BurnerNet examples" ${PROJECT_IS_TOP_LEVEL})
option(BURNERNET_OBFUSCATE_STRINGS "Obfuscate BurnerNet security-anchor string literals" ON)
option(BURNERNET_HARDEN_IMPORTS "Resolve libcurl dynamically instead of linking it into the import table" OFF)

if(MSVC)
    add_definitions(-D_HAS_EXCEPTIONS=0)
endif()

include(CTest)

if(DEFINED CMAKE_CXX_STANDARD AND CMAKE_CXX_STANDARD LESS 20)
    message(FATAL_ERROR "BurnerNet requires C++20 or newer. Set CMAKE_CXX_STANDARD to 20 or higher before adding this project.")
endif()

find_package(CURL REQUIRED)
if(BURNERNET_BUILD_TESTING OR BURNERNET_BUILD_INTEGRATION_TESTS)
    find_package(doctest CONFIG REQUIRED)
endif()

if(WIN32)
    find_library(BURNERNET_CRYPT32_LIBRARY NAMES crypt32)
    find_library(BURNERNET_WS2_32_LIBRARY NAMES ws2_32)
    if(NOT BURNERNET_CRYPT32_LIBRARY OR NOT BURNERNET_WS2_32_LIBRARY)
        message(FATAL_ERROR
            "BurnerNet requires the Windows SDK libraries crypt32 and ws2_32, but one or more were not found during configuration.")
    endif()
endif()

set(BURNERNET_RUNTIME_DIR "${CMAKE_BINARY_DIR}/bin")

set(BURNERNET_SOURCES
    src/builder.cpp
    src/detail/memory_hygiene.cpp
    src/detail/wiping_alloc_engine.cpp
    src/error.cpp
    src/curl/curl_session.cpp
    src/curl/curl_http_client.cpp
    src/curl/curl_http_client_callbacks.cpp
    src/curl/curl_http_client_options.cpp
    src/curl/transport_orchestrator.cpp
    src/internal/header_validation.cpp
    src/internal/openssl_sync.cpp
)

list(APPEND BURNERNET_SOURCES src/bootstrap/bootstrap_windows.cpp)

add_library(BurnerNet ${BURNERNET_SOURCES})
add_library(BurnerNet::BurnerNet ALIAS BurnerNet)

target_include_directories(BurnerNet
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
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
    target_compile_options(BurnerNet PRIVATE /W4 /permissive- /GR- /EHs-c-)
else()
    target_compile_options(BurnerNet PRIVATE -Wall -Wextra -Wpedantic -Werror -fno-rtti -fno-exceptions)
endif()

if(BURNERNET_HARDEN_IMPORTS AND WIN32)
    get_target_property(BURNERNET_CURL_INCLUDE_DIRS CURL::libcurl INTERFACE_INCLUDE_DIRECTORIES)
    if(BURNERNET_CURL_INCLUDE_DIRS)
        foreach(BURNERNET_CURL_INCLUDE_DIR IN LISTS BURNERNET_CURL_INCLUDE_DIRS)
            target_include_directories(BurnerNet PUBLIC
                $<BUILD_INTERFACE:${BURNERNET_CURL_INCLUDE_DIR}>
            )
        endforeach()
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
            ${BURNERNET_CRYPT32_LIBRARY}
            ${BURNERNET_WS2_32_LIBRARY}
    )
else()
    # CMAKE_DL_LIBS provides -ldl (or equivalent) for dlsym used in
    # TryApplyOpenSSLHooks on non-Windows platforms.
    if(CMAKE_DL_LIBS)
        target_link_libraries(BurnerNet PRIVATE ${CMAKE_DL_LIBS})
    endif()
endif()

function(burnernet_configure_runtime target_name)
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${BURNERNET_RUNTIME_DIR}"
    )

    if(WIN32 AND NOT (DEFINED VCPKG_TARGET_TRIPLET AND VCPKG_TARGET_TRIPLET MATCHES "static"))
        set(BURNERNET_RUNTIME_DLL_DIR "$<IF:$<CONFIG:Debug>,${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/debug/bin,${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin>")
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:${target_name}>/redist"
            COMMAND ${CMAKE_COMMAND}
                "-DBURNER_RUNTIME_DLL_DIRS=${BURNERNET_RUNTIME_DLL_DIR}"
                -DBURNER_SOURCE_DIR="$<TARGET_FILE_DIR:${target_name}>"
                -DBURNER_REDIST_DIR="$<TARGET_FILE_DIR:${target_name}>/redist"
                -DBURNER_COPY_TO_SOURCE_DIR=ON
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
        target_compile_options(${target_name} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

if(BURNERNET_BUILD_EXAMPLES)
    add_subdirectory(examples)
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
        target_compile_options(BurnerNetTests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(BurnerNetTests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burnernet_configure_runtime(BurnerNetTests)
    set_target_properties(BurnerNetTests PROPERTIES FOLDER "Tests")
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
        target_compile_options(BurnerNetIntegrationTests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(BurnerNetIntegrationTests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()
    burnernet_configure_runtime(BurnerNetIntegrationTests)
    set_target_properties(BurnerNetIntegrationTests PROPERTIES FOLDER "Tests")
    add_test(NAME BurnerNet.Integration COMMAND BurnerNetIntegrationTests)

    add_custom_target(run_integration_tests
        COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG> --output-on-failure -R BurnerNet.Integration
        DEPENDS BurnerNetIntegrationTests
        USES_TERMINAL
        COMMENT "Run BurnerNet integration tests"
    )
    set_target_properties(run_integration_tests PROPERTIES FOLDER "Tests")
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
