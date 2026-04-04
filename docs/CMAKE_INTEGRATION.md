# BurnerNet CMake Integration

This document covers practical integration of BurnerNet into a downstream CMake project.

It focuses on three Windows/MSVC workflows:

1. recommended local subproject integration with normal curl linking
2. advanced bootstrap-based runtime loading with `InitializeNetworkingRuntime(...)`
3. local or package-style integration with curl linked statically

BurnerNet uses its own `KernelResolver` path for hardened Windows resolution, so downstream CMake consumers do not need any extra import-hiding package.

## What Is Static vs Dynamic

There are two separate things to think about:

1. `burner-net` itself
2. curl/OpenSSL/zlib underneath it

These can vary independently.

### `burner-net` itself

If you add BurnerNet with `add_subdirectory(...)`, then BurnerNet is built as part of your own CMake build graph.

That means:

- BurnerNet is integrated into your app build as a normal CMake library target
- the consumer links `BurnerNet::BurnerNet`
- the consumer does **not** need to re-list BurnerNet `.cpp` files manually

If you consume an installed package with `find_package(BurnerNet CONFIG REQUIRED)`, BurnerNet is still a normal CMake target from the consumer perspective, but the build boundary is now package-based instead of sibling-source based.

### curl/OpenSSL/zlib

The curl stack can be integrated in different ways:

- **dynamic via normal linking:** link `CURL::libcurl`, then ship the required runtime DLLs
- **dynamic via bootstrap:** set `BURNERNET_HARDEN_IMPORTS=1` and preload the runtime DLLs with `InitializeNetworkingRuntime(...)`
- **static:** link curl and its dependency stack statically, so no curl/OpenSSL/zlib runtime DLLs are needed

So the important distinction is:

- BurnerNet via CMake subproject/package is still a normal linked target
- curl can still be **dynamic** or **static**

## Scope

This guide assumes:

- CMake consumer project
- C++20 enabled
- Windows target
- curl provided either by vcpkg manifest mode or by a local prebuilt dependency prefix

## `VCPKG_ROOT` note

If you use the recommended vcpkg-toolchain workflow, make sure `VCPKG_ROOT` is set in your environment.

Example:

- `VCPKG_ROOT=C:\path\to\vcpkg`

Why this matters:

- the consumer `CMakePresets.json` typically points `CMAKE_TOOLCHAIN_FILE` at `$env{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake`
- if `VCPKG_ROOT` is not set correctly, the preferred manifest-based CMake path will not configure correctly

In vcpkg terms:

- `VCPKG_ROOT` can be set to the root directory of the vcpkg instance
- it is used when the vcpkg executable is not already being resolved from a valid root and no explicit `--vcpkg-root` override is supplied

This guide does **not** replace the Visual Studio `.vcxproj` path. If your downstream project is MSBuild-first, see [VISUAL_STUDIO_INTEGRATION.md](VISUAL_STUDIO_INTEGRATION.md).

## Integration Modes

**Which mode should I choose?**

- Want it to just work? **Mode 1.**
- Want a single `.exe` with no extra DLLs? **Mode 3.**
- Building something that needs to hide its dependencies? **Mode 2.**

### Mode 1: Local subproject integration with consumer-owned dependencies (Recommended)

Use this when:

- you have the BurnerNet source checkout available
- your downstream project already uses CMake
- you want the consumer project to own dependency resolution through its own vcpkg manifest/toolchain flow
- you want the cleanest local dev and smoke-test integration path

In this mode:

- BurnerNet is added with `add_subdirectory(...)`
- the consumer links `BurnerNet::BurnerNet`
- the consumer owns `curl` resolution through its own `vcpkg.json` and vcpkg toolchain
- BurnerNet carries its own include paths and compile definitions
- BurnerNet carries its hardened resolver implementation inside the library sources
- curl is usually **dynamic**
- runtime DLL staging is typically handled by the consumer's dependency manager flow

This is the recommended CMake path for most local development and integration work.

### Mode 2: Bootstrap runtime loading

Use this when:

- you want BurnerNet consumed through CMake
- you do **not** want curl/OpenSSL/zlib resolved through the normal import-table path
- you want to preload those runtime DLLs from a custom directory

In this mode:

- BurnerNet is still consumed as a normal CMake target
- `BURNERNET_HARDEN_IMPORTS=1`
- BurnerNet resolves curl and selected Windows exports dynamically after you call `InitializeNetworkingRuntime(...)`
- curl is still **dynamic**
- runtime DLLs live in your chosen redist folder instead of the normal executable-adjacent layout

This mode is more configurable, but it is also the more advanced integration path.

### Mode 3: Integration with curl linked statically

Use this when:

- you want to avoid shipping curl/OpenSSL/zlib runtime DLLs
- you already have a true static curl dependency build available
- you want either local subproject consumption or package consumption with static dependencies

In this mode:

- BurnerNet is still consumed as a normal CMake target
- `BURNERNET_HARDEN_IMPORTS=0`
- curl is **static**
- no curl/OpenSSL/zlib runtime DLLs are required at deployment time

This is usually the simplest deployment model once a static curl dependency build is available, but it depends on having the correct static curl and dependency libraries prepared up front.

## Prerequisites

For any mode, you need:

- C++20 enabled in the consumer project
- BurnerNet available as either source or installed package
- curl available to CMake
- curl runtime/import libraries or runtime DLLs available according to the mode you choose

Typical local folders for sibling-repo integration:

- BurnerNet source: `burner-net/`
- curl package config: somewhere under your dependency prefix or package manager output
- curl runtime DLLs: whatever runtime set your active architecture/configuration requires

## Recommended Downstream Setup

### Option A: vcpkg manifest mode

This is the preferred "dev no think" path.

Consumer project sketch:

```cmake
cmake_minimum_required(VERSION 3.21)
project(MyApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(external/burner-net)

add_executable(MyApp main.cpp)
target_link_libraries(MyApp PRIVATE BurnerNet::BurnerNet)
```

With vcpkg manifest mode active in the consumer project:

- `find_package(CURL REQUIRED)` resolves normally inside BurnerNet
- vcpkg AppLocal deployment usually stages the required runtime DLLs automatically
- the consumer usually does **not** need custom DLL copy logic

### Option B: local sibling-repo fallback via `CMAKE_PREFIX_PATH`

Use this when you explicitly want to reuse the already-built curl/OpenSSL/zlib tree from a local BurnerNet checkout instead of letting the consumer own dependency resolution.

Consumer project sketch:

```cmake
cmake_minimum_required(VERSION 3.21)
project(MyApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BURNERNET_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../burner-net" CACHE PATH "")
set(BURNERNET_DEP_PREFIX
    "/path/to/dependency/prefix"
    CACHE PATH "")

list(PREPEND CMAKE_PREFIX_PATH "${BURNERNET_DEP_PREFIX}")

set(BURNERNET_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BURNERNET_BUILD_INTEGRATION_TESTS OFF CACHE BOOL "" FORCE)
set(BURNERNET_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

add_subdirectory("${BURNERNET_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/_deps/burner-net")

add_executable(MyApp main.cpp)
target_link_libraries(MyApp PRIVATE BurnerNet::BurnerNet)
```

This is valid as a fallback for smoke tests and local integration work, but it has important tradeoffs:

- vcpkg AppLocal deployment is usually not driving the consumer build directly
- it is more brittle than the consumer-owned manifest/toolchain path
- it should not be the primary downstream recommendation

### Option C: installed package consumption

Use this when BurnerNet has already been installed somewhere reachable through `CMAKE_PREFIX_PATH`.

Consumer project sketch:

```cmake
cmake_minimum_required(VERSION 3.21)
project(MyApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(BurnerNet CONFIG REQUIRED)

add_executable(MyApp main.cpp)
target_link_libraries(MyApp PRIVATE BurnerNet::BurnerNet)
```

This is the cleanest long-term dependency-managed path once you have a proper install/package workflow in place.

## Runtime DLL Staging

### Preferred path: let the consumer dependency manager handle it

If your consumer uses vcpkg manifest mode with the vcpkg CMake toolchain, prefer that.

That usually gives you:

- `CURL::libcurl` resolution during configure
- automatic runtime DLL staging during build for dynamic triplets

This is the cleanest downstream story.

### Local subproject helper

When BurnerNet is added via `add_subdirectory(...)`, BurnerNet exposes this helper:

- `burnernet_configure_runtime(<target>)`

It is intended for build-tree usage and sets:

- runtime output directory to BurnerNet's configured runtime folder
- Windows `redist/` DLL staging for dynamic builds

Example:

```cmake
add_executable(MyApp main.cpp)
target_link_libraries(MyApp PRIVATE BurnerNet::BurnerNet)
burnernet_configure_runtime(MyApp)
```

This helper is useful for local subproject integration.

It is **not** a replacement for consumer-owned dependency management. For installed/package consumption or manifest-based downstream builds, prefer the consumer's own dependency-management/runtime-staging mechanism.

### Manual fallback

If you explicitly point `CMAKE_PREFIX_PATH` at a sibling repo's already-built `vcpkg_installed` tree instead of using your own manifest/toolchain-driven dependency flow, you may still need to manually verify or adjust runtime DLL staging for:

- `libcurl*.dll`
- `libssl*.dll`
- `libcrypto*.dll`
- `zlib*.dll`

from the local dependency `debug/bin` or `bin` folder into your executable directory or redist folder.

## Bootstrap Runtime Loading Setup

Use this only when you intentionally want to control where curl/OpenSSL/zlib DLLs are loaded from.

### Required project settings

1. Consume BurnerNet as a target.
2. Provide curl headers.
3. Do **not** rely on the normal curl import-table path.
4. Stage the runtime DLLs in a custom folder, for example:
   - your curl runtime DLL
   - the TLS/backend runtime DLLs required by that curl build
   - any compression/support DLLs required by that curl build

### Configure-time option

Set:

- `BURNERNET_HARDEN_IMPORTS=ON`

### App code requirement

Before building a BurnerNet client, call `InitializeNetworkingRuntime(...)`.

Example:

```cpp
#include <filesystem>

#include "burner/net/bootstrap.h"

int main() {
    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Dynamic;
    boot.dependency_directory = std::filesystem::current_path() / "redist";
    // Use the exact filenames emitted by your dependency set for the active
    // architecture/configuration.
    boot.dependency_dlls = {
        L"libcurl-d.dll",
        L"libssl-3-x64.dll",
        L"libcrypto-3-x64.dll",
        L"zlibd1.dll",
    };
    boot.integrity_policy.enabled = true;
    boot.integrity_policy.fail_closed = true;

    auto init = burner::net::InitializeNetworkingRuntime(boot);
    if (!init.success) {
        return 1;
    }

    return 0;
}
```

## Windows System Libraries

On Windows, BurnerNet resolves these system libraries explicitly during configure:

- `bcrypt`
- `crypt32`
- `ws2_32`

This avoids fragile reliance on shell-specific implicit linker search paths and makes MSVC/Ninja/WSL-adjacent environments more robust.

## Summary

For CMake consumers, the recommended order is:

1. let the consumer own its own `vcpkg.json` and vcpkg toolchain flow
2. consume BurnerNet as a normal CMake target
3. prefer `add_subdirectory(...)` for local sibling-repo dev and smoke tests
4. treat `CMAKE_PREFIX_PATH` reuse of BurnerNet's private dependency tree as fallback only
5. use `burnernet_configure_runtime(...)` as a build-tree helper when needed
6. reserve bootstrap runtime loading for advanced custom redist scenarios
