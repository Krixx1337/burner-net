# BurnerNet Visual Studio Source-Drop Example

This example shows how to integrate BurnerNet into a Visual Studio project without CMake by adding BurnerNet's `.cpp` files directly to the consumer project.

BurnerNet is compiled inside the consumer executable. The project does not consume a prebuilt `BurnerNet.lib`.

The project file is kept in sync with BurnerNet's current core source set, including the split curl transport files such as `curl_session.cpp`, `curl_http_client_callbacks.cpp`, `curl_http_client_options.cpp`, and `transport_orchestrator.cpp`.

## Prerequisites

- Visual Studio 2022
- vcpkg with curl installed for the architecture you want to build
- `vcpkg install curl[openssl]:x64-windows`

For 32-bit builds, install the matching x86 triplet instead.

## Files

- `vs-consumer.sln`
- `vs-consumer.vcxproj`
- `vs-consumer.vcxproj.filters`
- `vs-consumer.cpp`

## What This Demonstrates

This project follows BurnerNet's Visual Studio Mode 1 integration:

- BurnerNet source files are compiled directly into the consumer executable
- `BURNERNET_HARDEN_IMPORTS=0`
- `_HAS_EXCEPTIONS=0` is defined for MSVC to match the main project hardening setup
- curl is linked through the normal vcpkg/MSBuild import-library path
- curl/OpenSSL/zlib runtime DLLs are expected to resolve through the standard Visual Studio or vcpkg app-local flow

## How To Use It

1. Open `examples/vs-consumer/vs-consumer.sln` in Visual Studio 2022.
2. Ensure vcpkg integration is active for MSBuild.
3. Select the architecture that matches your curl installation.
4. Build and run `vs-consumer`.

If the environment is set up correctly, the example will build BurnerNet source files directly inside the project and perform a request to `https://example.com`.

## Troubleshooting

- If the linker cannot find `libcurl.lib` or `libcurl-d.lib`, your vcpkg MSBuild integration is not active or curl is not installed for the selected triplet.
- If you add BurnerNet source files manually to another Visual Studio project, keep the file list aligned with the root [`CMakeLists.txt`](/mnt/e/Projects/CPP/burner-net/CMakeLists.txt) source list. `CurlHttpClient` now depends on multiple `src/curl/*.cpp` translation units, not just `curl_http_client.cpp`.
- Match the Visual Studio target architecture to your curl installation, for example `x64` with `x64-windows` or `x86` with `x86-windows`.
- If the program starts but runtime DLLs are missing, verify that the selected vcpkg triplet uses the expected dynamic curl package layout.
