# BurnerNet CMake Consumer Example

This example shows the recommended CMake consumer path for BurnerNet:

- consumer-owned `vcpkg.json`
- consumer-owned vcpkg toolchain/presets
- local BurnerNet source consumed via `add_subdirectory(...)`
- linking against `BurnerNet::BurnerNet`

## Prerequisites

- Visual Studio with CMake support
- `VCPKG_ROOT` set in your environment
- a working vcpkg installation at that path

Example:

- `VCPKG_ROOT=C:\path\to\vcpkg`

## Project Layout

- `CMakeLists.txt`
- `CMakePresets.json`
- `vcpkg.json`
- `cmake-consumer.cpp`

## What It Does

The example:

1. adds the local BurnerNet repo from `../..`
2. disables BurnerNet's own tests/examples in the consumer build
3. links `BurnerNet::BurnerNet`
4. performs a live request to `https://example.com`

## How To Use It

1. Open this folder in Visual Studio:
   - `examples/cmake-consumer`
2. Let CMake configure the `x64-debug` preset.
3. Build `BurnerNetCMakeExample`.
4. Run the executable.

If the environment is correct, you should see output similar to:

```text
BurnerNet version: 0.1.0
Sending request to https://example.com...
Response code: 200
Transport succeeded securely.
```

## Notes

- This example demonstrates the preferred open-source-ready CMake path.
- `BURNERNET_DEP_PREFIX` exists only as an optional fallback for local smoke testing.
- For broader integration guidance, see `docs/CMAKE_INTEGRATION.md`.
