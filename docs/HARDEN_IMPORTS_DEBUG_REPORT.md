# Harden Imports Debug Report

## Scope

This report documents the failures encountered while validating the hardened-imports path through the CMake consumer example and the changes made to get it working.

Validated scenario:

- example: `examples/cmake-consumer`
- presets: `x64-debug-harden-imports` and `x64-release-harden-imports`
- mode: `BURNERNET_HARDEN_IMPORTS=ON`
- runtime model: bootstrap-based dynamic loading from `redist/`

Final observed working result:

- `BurnerNetCMakeExample.exe` bootstraps from `redist/`
- BurnerNet client builds successfully
- request to `https://example.com` completes with HTTP 200

## Initial Symptoms

The harden-imports test initially failed in several different ways depending on how far execution got:

1. CMake configure/generate errors in the consumer example.
2. Visual Studio / CMake `EXEC` post-build failures during runtime DLL staging.
3. Bootstrap initialization failure before any request was sent.
4. Client build failure after bootstrap succeeded.

These were not separate unrelated problems. They were a chain of issues in the harden-imports integration path.

## Root Causes

## 1. BurnerNet exported a build-tree curl include path into its public interface

### Symptom

The consumer hit CMake errors like:

- `INTERFACE_INCLUDE_DIRECTORIES property contains path ... vcpkg_installed/.../include`
- path rejected because it was inside the build tree

### Root issue

In the root [`CMakeLists.txt`](/mnt/e/Projects/CPP/burner-net/CMakeLists.txt), when `BURNERNET_HARDEN_IMPORTS=ON`, BurnerNet read curl include directories from `CURL::libcurl` and added them to `BurnerNet` as a raw public include path.

That is acceptable for the current build tree, but not for an exported/public interface, especially when the include path comes from a downstream consumer build directory.

### Fix

The curl include directories are now added as `BUILD_INTERFACE` only.

Effect:

- downstream `add_subdirectory(...)` builds still work
- BurnerNet no longer exports consumer-build-tree paths as public interface data

## 2. Runtime DLL staging relied on brittle `TARGET_RUNTIME_DLLS` command expansion

### Symptom

The consumer harden-imports build produced opaque post-build `EXEC` failures.

### Root issue

The project used:

- `cmake -E copy_if_different $<TARGET_RUNTIME_DLLS:...> ...`

directly in custom commands.

That pattern is fragile when:

- the DLL list is empty
- the target shape is not what CMake expects
- imported targets do not expose runtime DLLs in a compatible form
- Visual Studio/CMake wraps the custom command in an opaque `EXEC` layer

### Fix

The staging logic was moved to [`cmake/SyncRedist.cmake`](/mnt/e/Projects/CPP/burner-net/cmake/SyncRedist.cmake), and that script was extended to support:

- explicit DLL file lists
- runtime DLL directories
- optional copy to executable directory
- redist-only copy

The root helper [`burnernet_configure_runtime(...)`](/mnt/e/Projects/CPP/burner-net/CMakeLists.txt) now calls the script instead of expanding `copy_if_different` directly on generator expression output.

Effect:

- runtime staging is more tolerant
- the consumer no longer depends on a brittle direct `TARGET_RUNTIME_DLLS` copy command

## 3. The temporary CMake consumer harden-imports test asked for `TARGET_RUNTIME_DLLS:CURL::libcurl`

### Symptom

CMake reported:

- `Objects of target "CURL::libcurl" referenced but no such target exists`

### Root issue

The temporary example used `TARGET_RUNTIME_DLLS:CURL::libcurl` in a post-build command.

Even though `find_package(CURL REQUIRED)` worked for BurnerNet, the imported target shape in the actual environment did not support that generator expression the way the example assumed.

### Fix

The example now stages DLLs from runtime directories instead of `TARGET_RUNTIME_DLLS:CURL::libcurl`.

Resolution logic:

- if `BURNERNET_DEP_PREFIX` is set:
  - use `<prefix>/debug/bin` for Debug
  - use `<prefix>/bin` for Release
- otherwise:
  - use `${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/debug/bin`
  - or `${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin`

Effect:

- DLL staging no longer depends on the exact structure of `CURL::libcurl`
- the example works with the vcpkg layout actually used by the consumer build

## 4. Windows bootstrap incorrectly treated `SetDefaultDllDirectories` support as mandatory

### Symptom

The sample printed bootstrap failure with raw code `25`.

That raw code maps to:

- `ErrorCode::BootstrapDllDirs`

### Root issue

In [`src/bootstrap/bootstrap_windows.cpp`](/mnt/e/Projects/CPP/burner-net/src/bootstrap/bootstrap_windows.cpp), the bootstrap path did two things that were too strict:

1. it required the loader-import bundle to contain `SetDefaultDllDirectories`
2. it treated `SetDefaultDllDirectories(...)` failure as fatal

But the actual loading path already used explicit `LoadLibraryExW(...)` flags:

- `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`
- `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`
- `LOAD_LIBRARY_SEARCH_USER_DIRS`

and also used `AddDllDirectory(...)`.

That means `SetDefaultDllDirectories(...)` is useful, but not the correct hard failure point in this bootstrap flow.

### Fix

Two changes were made:

1. `SetDefaultDllDirectories` is no longer part of the readiness requirement
2. calling `SetDefaultDllDirectories(...)` is now best-effort, not fatal

Effect:

- the bootstrap path no longer dies early on systems/configurations where that call is unavailable or rejected

## 5. Bootstrap loader-function resolution through lazy-import indirection was brittle

### Symptom

Even after relaxing the DLL-directory logic, bootstrap still failed with `BootstrapDllDirs`.

### Root issue

The bootstrap code resolved these Windows APIs indirectly through the lazy-import path:

- `SetDefaultDllDirectories`
- `AddDllDirectory`
- `LoadLibraryExW`
- `GetModuleFileNameW`
- `FreeLibrary`

That added an unnecessary extra layer in a part of the code that already had direct access to Win32 APIs.

For bootstrap, this indirection proved to be the unstable point.

### Fix

The bootstrap path in [`src/bootstrap/bootstrap_windows.cpp`](/mnt/e/Projects/CPP/burner-net/src/bootstrap/bootstrap_windows.cpp) now uses direct Win32 calls instead of the lazy-import wrapper.

Effect:

- bootstrap now reliably progresses past the DLL-directory stage
- the failure moved forward to the next real issue instead of dying in the loader-API setup

## 6. The harden-imports curl resolver defaulted to the wrong module in Debug builds

### Symptom

After bootstrap succeeded, the client build failed with raw code `27`.

That raw code maps to:

- `ErrorCode::CurlApiIncomplete`

### Root issue

The harden-imports session builder defaults to resolving curl exports from:

- `libcurl.dll`

But the Debug consumer was staging:

- `libcurl-d.dll`

So in Debug mode, the configured module name and the actual staged module name did not match.

### Fix

The CMake consumer example now sets the curl module explicitly in harden-imports mode:

- Debug: `libcurl-d.dll`
- Release: `libcurl.dll`

This is done through:

- [`ClientBuilder::WithCurlModuleName(...)`](/mnt/e/Projects/CPP/burner-net/include/burner/net/builder.h)

Effect:

- the harden-imports client now targets the correct runtime DLL for each configuration

## 7. Curl export resolution through lazy-importer was the final unstable step

### Symptom

Even after setting the correct curl module name, the client still failed with:

- `raw=27`
- `CurlApiIncomplete`

### Root issue

The harden-imports path in [`src/curl/curl_session.cpp`](/mnt/e/Projects/CPP/burner-net/src/curl/curl_session.cpp) used:

- lazy-imported `GetModuleHandleA`
- lazy-importer-based export lookup for curl functions

That left two moving parts:

1. finding the loaded module
2. resolving the exports from that module

In practice, this path did not produce a complete curl API table in the tested environment.

### Fix

The harden-imports curl session path now uses direct Win32 APIs:

- `GetModuleHandleA(...)` to find the configured curl module
- `GetProcAddress(...)` to resolve:
  - `curl_easy_init`
  - `curl_easy_cleanup`
  - `curl_easy_reset`
  - `curl_easy_setopt`
  - `curl_easy_perform`
  - `curl_easy_getinfo`
  - `curl_slist_append`
  - `curl_slist_free_all`
  - `curl_easy_strerror`

Effect:

- the curl API table resolves completely
- `CurlApiIncomplete` is eliminated
- the client successfully initializes under harden-imports mode

## 8. Non-Windows harden-imports builds had dead-code warnings promoted to errors

### Symptom

While validating the branch on Linux, the harden-imports path failed local compile checks under `-Werror` because Windows-only resolver helpers were present but unused.

### Root issue

The code was structured so that:

- harden-imports branches compiled on non-Windows
- but some helper functions were only meaningful on Windows

This produced `unused-function` / `unused-parameter` warnings that were promoted to errors.

### Fix

The harden-imports session path in [`src/curl/curl_session.cpp`](/mnt/e/Projects/CPP/burner-net/src/curl/curl_session.cpp) was adjusted so that:

- Windows-only resolver code is compiled only on Windows
- non-Windows harden-imports builds fall back cleanly to the wrapped curl API path

Effect:

- local validation became reliable
- the branch is cleaner across toolchains

## Why the Final Build Worked

The final successful run happened because all parts of the chain were aligned:

1. the consumer example staged the runtime DLLs into `redist/`
2. bootstrap used direct Win32 APIs and accepted best-effort `SetDefaultDllDirectories(...)`
3. the bootstrap config discovered the staged `.dll` files and loaded them from `redist/`
4. the client explicitly targeted the correct curl runtime DLL for the build configuration
5. curl exports were resolved with `GetProcAddress(...)` directly from the loaded module

Once those conditions were true, the example could:

- initialize BurnerNet runtime
- build the client
- perform a request successfully under harden-imports mode

## Files Changed

- [`CMakeLists.txt`](/mnt/e/Projects/CPP/burner-net/CMakeLists.txt)
- [`cmake/SyncRedist.cmake`](/mnt/e/Projects/CPP/burner-net/cmake/SyncRedist.cmake)
- [`examples/cmake-consumer/CMakeLists.txt`](/mnt/e/Projects/CPP/burner-net/examples/cmake-consumer/CMakeLists.txt)
- [`examples/cmake-consumer/CMakePresets.json`](/mnt/e/Projects/CPP/burner-net/examples/cmake-consumer/CMakePresets.json)
- [`examples/cmake-consumer/README.md`](/mnt/e/Projects/CPP/burner-net/examples/cmake-consumer/README.md)
- [`examples/cmake-consumer/cmake-consumer.cpp`](/mnt/e/Projects/CPP/burner-net/examples/cmake-consumer/cmake-consumer.cpp)
- [`examples/vs-consumer/vs-consumer.vcxproj`](/mnt/e/Projects/CPP/burner-net/examples/vs-consumer/vs-consumer.vcxproj)
- [`examples/vs-consumer/vs-consumer.vcxproj.filters`](/mnt/e/Projects/CPP/burner-net/examples/vs-consumer/vs-consumer.vcxproj.filters)
- [`examples/vs-consumer/README.md`](/mnt/e/Projects/CPP/burner-net/examples/vs-consumer/README.md)
- [`include/burner/net/detail/pointer_mangling.h`](/mnt/e/Projects/CPP/burner-net/include/burner/net/detail/pointer_mangling.h)
- [`src/bootstrap/bootstrap_windows.cpp`](/mnt/e/Projects/CPP/burner-net/src/bootstrap/bootstrap_windows.cpp)
- [`src/curl/curl_session.cpp`](/mnt/e/Projects/CPP/burner-net/src/curl/curl_session.cpp)
- [`tests/unit_tests.cpp`](/mnt/e/Projects/CPP/burner-net/tests/unit_tests.cpp)

Not all of these files were part of the final harden-imports runtime fix directly. Some were earlier requested fixes completed in the same working session.

## Recommended Follow-Up

These follow-ups would improve maintainability:

1. keep the direct Win32 bootstrap and curl-resolution approach for the hardened-imports path
2. document that Debug harden-imports builds require `libcurl-d.dll`
3. consider making `WithCurlModuleName(...)` part of a higher-level harden-imports helper for examples
4. keep `SyncRedist.cmake` as the canonical runtime staging path instead of duplicating ad hoc `copy_if_different` command sequences
5. consider adding a Windows-only smoke test for:
   - bootstrap success
   - client build success under `BURNERNET_HARDEN_IMPORTS=ON`

## Bottom Line

The real root issue was not a single bad DLL or one bad preset. It was a stack of assumptions in the harden-imports integration path:

- exported build-tree include paths
- brittle runtime DLL staging
- strict bootstrap DLL-directory requirements
- lazy-import indirection in the wrong places
- wrong curl module name in Debug
- non-direct export resolution for the loaded curl module

Once those assumptions were removed and the runtime path was reduced to:

- direct Win32 bootstrap
- explicit runtime staging
- explicit curl module selection
- direct `GetProcAddress(...)`

the harden-imports path behaved correctly.
