# CMakeList.txt : CMake project for cmake-consumer, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.21)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(BurnerNetCMakeExample LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BURNERNET_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." CACHE PATH
    "Path to the local burner-net source checkout")
set(BURNERNET_DEP_PREFIX
    ""
    CACHE PATH
    "Optional fallback path to a local dependency prefix containing curl/OpenSSL/zlib for burner-net")

if(NOT EXISTS "${BURNERNET_SOURCE_DIR}/CMakeLists.txt")
  message(FATAL_ERROR
      "BURNERNET_SOURCE_DIR does not point to a burner-net checkout: ${BURNERNET_SOURCE_DIR}")
endif()

if(BURNERNET_DEP_PREFIX)
  if(NOT EXISTS "${BURNERNET_DEP_PREFIX}/share/curl/CURLConfig.cmake")
    message(FATAL_ERROR
        "BURNERNET_DEP_PREFIX does not contain the expected curl package config: "
        "${BURNERNET_DEP_PREFIX}/share/curl/CURLConfig.cmake")
  endif()
  list(PREPEND CMAKE_PREFIX_PATH "${BURNERNET_DEP_PREFIX}")
endif()

set(BURNERNET_BUILD_TESTING OFF CACHE BOOL "Disable burner-net tests in this example consumer" FORCE)
set(BURNERNET_BUILD_INTEGRATION_TESTS OFF CACHE BOOL "Disable burner-net integration tests in this example consumer" FORCE)
set(BURNERNET_BUILD_EXAMPLES OFF CACHE BOOL "Disable burner-net examples in this example consumer" FORCE)

add_subdirectory("${BURNERNET_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/_deps/burner-net")

# Add source to this project's executable.
add_executable(BurnerNetCMakeExample "cmake-consumer.cpp" "cmake-consumer.h")
target_link_libraries(BurnerNetCMakeExample PRIVATE BurnerNet::BurnerNet)
burnernet_configure_runtime(BurnerNetCMakeExample)

# TODO: Add tests and install targets if needed.
