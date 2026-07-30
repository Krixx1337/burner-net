# BurnerNet on Linux

BurnerNet is Windows-focused but supports its portable owned-memory wiping,
string obfuscation, and stack-isolation paths on Linux. v1.3 does not claim full
forensic parity: Maximum Ghost libcurl/OpenSSL allocator interception is
Windows-only.

## Feature Support Matrix

| Feature | Linux Status | Benefit |
| :--- | :--- | :--- |
| **BurnerNet-owned memory wiping** | ✅ Supported | Wipes BurnerNet-owned request, response, credential, and temporary state. |
| **Maximum Ghost backend allocators** | ❌ Windows Only | Linux v1.3 does not claim control over all libcurl/OpenSSL allocations. |
| **Stack Isolation** | ✅ Full Support | Severs the call stack to hide your app logic from tracers. |
| **String Obfuscation** | ✅ Full Support | URLs and security strings are encrypted at compile-time. |
| **Windows-style Hardened Imports** | N/A | The Windows import-hiding/bootstrap path is Windows-specific. Linux uses the normal platform linker/runtime model. |
| **Deep Stealth** | ❌ Windows Only | Manual PEB/PE parsing is exclusive to the Windows path. |

## Quick Start (Ubuntu/Debian)

### 1. Install Dependencies

BurnerNet requires the development headers for `libcurl` and `OpenSSL`.

```bash
sudo apt update
sudo apt install libcurl4-openssl-dev libssl-dev build-essential cmake
```

### 2. Build via CMake

```bash
mkdir build && cd build
cmake .. -DBURNERNET_BUILD_EXAMPLES=ON
make -j$(nproc)
```

## Security Implementation Details

Linux v1.3 uses BurnerNet-owned wiping storage and best-effort OpenSSL
worker-thread cleanup. It does not enable the process-global allocator contract
used by Windows Maximum Ghost mode.

## Integration

To enable maximum hardening on Linux, ensure you use the following builder options:

```cpp
auto client = burner::net::ClientBuilder()
    .WithStackIsolation(true) // Enable Dynamic Analysis resistance
    .Build();
```

Notes:

- `InitializeNetworkingRuntime(...)` is a Windows bootstrap API and is not part of the normal Linux integration path.
- `BURNERNET_MAXIMUM_GHOST=ON` is rejected on Linux in v1.3.
- On Linux, focus on early client creation, short-lived transports, and application-owned trust decisions rather than Windows-specific loader controls.
