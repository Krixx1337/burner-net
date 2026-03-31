# BurnerNet Visual Studio Integration

This document covers practical integration of BurnerNet into a Visual Studio `.vcxproj` project.

It focuses on three Windows/MSVC workflows:

1. recommended standard source-drop with normal curl import-library linking
2. advanced bootstrap-based runtime loading with `InitializeNetworkingRuntime(...)`
3. source-drop with curl linked statically

## What Is Static vs Dynamic

There are two separate things to think about:

1. `burner-net` itself
2. curl/OpenSSL/zlib underneath it

These can vary independently.

### `burner-net` itself

If you add BurnerNet's `.cpp` files directly to your `.vcxproj`, then BurnerNet is compiled into your own executable or host DLL.

That means:

- BurnerNet is integrated **statically** into your app
- there is no separate `BurnerNet.dll`
- there is no separate prebuilt `BurnerNet.lib` consumer boundary at runtime

This document is primarily about that source-drop model.

### curl/OpenSSL/zlib

The curl stack can be integrated in different ways:

- **dynamic via normal linking:** link `libcurl.lib` / `libcurl-d.lib`, then ship the required runtime DLLs
- **dynamic via bootstrap:** set `BURNERNET_HARDEN_IMPORTS=1` and preload the runtime DLLs with `InitializeNetworkingRuntime(...)`
- **static:** link curl and its dependency stack as static libraries, so no curl/OpenSSL/zlib runtime DLLs are needed

So the important distinction is:

- BurnerNet source-drop usually means **BurnerNet static**
- curl can still be **dynamic** or **static**

## Scope

This guide assumes:

- Visual Studio / MSBuild consumer project
- C++20 enabled
- Windows target
- curl provided externally, typically through vcpkg or a local prebuilt dependency tree

This guide does **not** replace the CMake integration path. If your downstream project already uses CMake, that is still the cleanest dependency-managed setup.

## Integration Modes

**Which mode should I choose?**

- Want it to just work? **Mode 1.**
- Want a single `.exe` with no extra DLLs? **Mode 3.**
- Building something that needs to hide its dependencies? **Mode 2.**

### Mode 1: Standard source-drop (Recommended)

Use this when:

- you want BurnerNet compiled directly into your own `.exe` or `.dll`
- you are fine with curl/OpenSSL/zlib runtime DLLs being resolved in the normal way
- you want the simplest `dev no think` `.vcxproj` integration path

In this mode:

- BurnerNet source files are compiled directly inside your project
- BurnerNet itself is **static** inside your app
- `BURNERNET_HARDEN_IMPORTS=0`
- you link curl normally, typically through `libcurl.lib` or `libcurl-d.lib`
- curl is **dynamic**
- runtime DLLs usually sit next to the executable or are staged there by your dependency manager

This is the recommended Visual Studio path for most consumers.

### Mode 2: Bootstrap runtime loading

Use this when:

- you want BurnerNet compiled directly into your own `.exe` or `.dll`
- you do **not** want curl/OpenSSL/zlib resolved through the normal import-table path
- you want to preload those runtime DLLs from a custom directory

In this mode:

- BurnerNet source files are still compiled directly inside your project
- BurnerNet itself is **static** inside your app
- `BURNERNET_HARDEN_IMPORTS=1`
- BurnerNet resolves curl exports dynamically after you call `InitializeNetworkingRuntime(...)`
- curl is still **dynamic**
- runtime DLLs live in your chosen redist folder instead of the normal executable-adjacent layout

This mode is more configurable, but it is also the more advanced integration path.

### Mode 3: Source-drop with curl linked statically

Use this when:

- you want BurnerNet compiled directly into your own `.exe` or `.dll`
- you want to avoid shipping curl/OpenSSL/zlib runtime DLLs
- you already have a true static curl dependency build available

In this mode:

- BurnerNet source files are compiled directly inside your project
- BurnerNet itself is **static** inside your app
- `BURNERNET_HARDEN_IMPORTS=0`
- curl is **static**
- no curl/OpenSSL/zlib runtime DLLs are required at deployment time

This is usually the simplest deployment model once a static curl build is available, but it depends on having the correct static curl and dependency libraries prepared up front.

## Prerequisites

For either mode, you need:

- C++20 enabled in the consumer project
- BurnerNet headers available
- BurnerNet source files available
- curl headers available
- curl runtime/import libraries or runtime DLLs available according to the mode you choose

Typical local folders:

- BurnerNet headers: `burner-net/include`
- BurnerNet source: `burner-net/src`
- curl headers from vcpkg: `.../vcpkg_installed/x64-windows/include`
- curl debug import library: `.../vcpkg_installed/x64-windows/debug/lib/libcurl-d.lib`
- curl debug runtime DLLs: `.../vcpkg_installed/x64-windows/debug/bin/*.dll`

## BurnerNet Source Files To Add

For a normal Windows build, add these BurnerNet `.cpp` files to your `.vcxproj`:

- `src/builder.cpp`
- `src/detail/memory_hygiene.cpp`
- `src/error.cpp`
- `src/curl/curl_http_client.cpp`
- `src/http_factory.cpp`
- `src/internal/header_validation.cpp`
- `src/security/security_auditor.cpp`
- `src/bootstrap/bootstrap_windows.cpp`

## Include Directories

At minimum, add:

- `burner-net/include`

For source-drop integration, also add:

- `burner-net/src`

And add your curl include root, for example:

- `.../vcpkg_installed/x64-windows/include`

## Standard Source-Drop Setup

This is the lower-friction Visual Studio path.

### Required project settings

1. Add the BurnerNet `.cpp` files to the project.
2. Add the include directories listed above.
3. Add your curl import library directory to **Additional Library Directories**.
4. Link the appropriate curl import library:
   - Debug: usually `libcurl-d.lib`
   - Release: usually `libcurl.lib`

### Preprocessor definitions

Recommended minimum:

- `BURNER_ENABLE_CURL=1`
- `BURNERNET_HARDEN_IMPORTS=0`

Optional:

- `BURNERNET_OBFUSCATE_STRINGS=1`

### Windows system libraries

Under MSVC, BurnerNet auto-links the Windows subsystem libraries it needs with `#pragma comment(lib, ...)`.

That means you do **not** need to manually add:

- `ws2_32.lib`
- `crypt32.lib`
- `bcrypt.lib`
- `advapi32.lib`
- `secur32.lib`
- `iphlpapi.lib`
- `wldap32.lib`
- `normaliz.lib`

### Debug settings

BurnerNet now survives MSVC's default Debug mode with:

- `/ZI`
- Just My Code enabled

You do **not** need to switch to `/Zi` only to satisfy `BURNER_OBF_LITERAL(...)`.

### Runtime DLL layout

For this mode, curl/OpenSSL/zlib runtime DLLs should usually be available next to the executable, for example:

- `MyApp.exe`
- `libcurl-d.dll`
- `libssl-3-x64.dll`
- `libcrypto-3-x64.dll`
- `zlibd1.dll`

If you use vcpkg MSBuild integration, it may stage these automatically. If not, copy them in a post-build step.

## Bootstrap Runtime Loading Setup

Use this only when you intentionally want to control where curl/OpenSSL/zlib DLLs are loaded from.

### Required project settings

1. Add the BurnerNet `.cpp` files to the project.
2. Add the include directories listed above.
3. Provide curl headers.
4. Do **not** rely on the normal curl import-table path.
5. Stage the runtime DLLs in a custom folder, for example:
   - `MyApp\burner-redist\libcurl-d.dll`
   - `MyApp\burner-redist\libssl-3-x64.dll`
   - `MyApp\burner-redist\libcrypto-3-x64.dll`
   - `MyApp\burner-redist\zlibd1.dll`

### Preprocessor definitions

Required:

- `BURNER_ENABLE_CURL=1`
- `BURNERNET_HARDEN_IMPORTS=1`

Often required:

- `CURL_STATICLIB`

`CURL_STATICLIB` here is used so curl headers expose the right declarations while BurnerNet resolves the runtime exports itself.

### App code requirement

Before building a BurnerNet client, call `InitializeNetworkingRuntime(...)`.

Example:

```cpp
#include <filesystem>

#include "burner/net/bootstrap.h"

const auto exe_dir = std::filesystem::path(argv[0]).parent_path();

burner::net::BootstrapConfig boot{};
boot.link_mode = burner::net::LinkMode::Dynamic;
boot.dependency_directory = exe_dir / "burner-redist";
// Explicitly list the DLLs you package; BurnerNet no longer assumes any default names.
boot.dependency_dlls = {
    L"libcurl-d.dll",
    L"libssl-3-x64.dll",
    L"libcrypto-3-x64.dll",
    L"zlibd1.dll",
};
boot.integrity_policy.enabled = true;
boot.integrity_policy.integrity_provider =
    [](const std::filesystem::path& dll_path, const std::wstring& dll_name) {
        return VerifyPackagedRuntimeDll(dll_path, dll_name);
    };

const auto init = burner::net::InitializeNetworkingRuntime(boot);
if (!init.success) {
    return 1;
}
```

Only after that should you call:

- `ClientBuilder().Build()`
- or `CreateHttpClient(...)`

### Runtime DLL layout

In this mode, the DLLs do not need to sit next to the executable.

Example:

- `MyApp.exe`
- `burner-redist/libcurl-d.dll`
- `burner-redist/libssl-3-x64.dll`
- `burner-redist/libcrypto-3-x64.dll`
- `burner-redist/zlibd1.dll`

## Source-Drop With Curl Linked Statically

Use this mode when you have a static curl build and want BurnerNet source-drop integration without curl/OpenSSL/zlib runtime DLL deployment.

### Required project settings

1. Add the BurnerNet `.cpp` files to the project.
2. Add the include directories listed above.
3. Add the static curl and dependency library directories to **Additional Library Directories**.
4. Link the static curl library and the static dependency libraries provided by your curl build.

### Preprocessor definitions

Required:

- `BURNER_ENABLE_CURL=1`
- `BURNERNET_HARDEN_IMPORTS=0`
- `CURL_STATICLIB`

### Runtime DLL layout

None for curl/OpenSSL/zlib.

In this mode, you do not ship:

- `libcurl*.dll`
- `libssl*.dll`
- `libcrypto*.dll`
- `zlib*.dll`

because the curl stack is linked statically.

### Notes

- `InitializeNetworkingRuntime(...)` is not used in this mode.
- This mode depends entirely on how your static curl package was built and what additional static libraries it requires.
- If your static curl package is incomplete or mismatched, the linker will fail in the consumer project.

## Debug vs Release Notes

Be consistent about the runtime set:

- Debug consumers should use the Debug curl import library and Debug DLL names
- Release consumers should use the Release curl import library and Release DLL names

Typical examples:

- Debug import lib: `libcurl-d.lib`
- Debug DLL: `libcurl-d.dll`
- Release import lib: `libcurl.lib`
- Release DLL: `libcurl.dll`

Do not mix Debug and Release runtime sets in the same consumer configuration.

## Common Failure Cases

### Template errors around `BURNER_OBF_LITERAL(...)`

If you still see template failures here, check that:

- you are compiling the updated BurnerNet sources
- you are not accidentally mixing an older BurnerNet header snapshot into the project

### Unresolved external symbols for Windows networking/crypto APIs

Under MSVC, BurnerNet auto-links the required Windows subsystem libraries.

If you still see unresolved externals:

- confirm you are compiling `src/curl/curl_http_client.cpp`
- confirm MSVC is the active compiler
- confirm you are not excluding BurnerNet source files from the active configuration

### Missing curl headers

If compilation fails on `<curl/curl.h>`:

- your curl include path is not configured
- BurnerNet does not supply curl headers by itself

### Runtime failure loading curl DLLs in bootstrap mode

Check:

- `BURNERNET_HARDEN_IMPORTS=1`
- your runtime folder path matches `boot.dependency_directory`
- the staged DLL names match `boot.dependency_dlls`
- the DLL architecture matches the executable architecture

### Runtime failure in standard source-drop mode

Check:

- curl/OpenSSL/zlib DLLs are next to the executable, or otherwise resolvable
- you linked the correct import library for the active configuration

### Linker failure in static-curl mode

Check:

- `CURL_STATICLIB` is defined
- you linked the correct static curl library for the active configuration
- the required static dependency libraries from your curl build are also linked
- your static curl build matches the executable architecture and runtime model

## Practical Recommendation

If you are staying in `.vcxproj` land, start with:

- standard source-drop
- normal curl import-library linking
- executable-adjacent runtime DLLs

Only move to bootstrap runtime loading when you explicitly need custom runtime DLL placement or controlled preload behavior.
