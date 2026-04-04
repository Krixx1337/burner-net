# BurnerNet on Linux

While BurnerNet is a Windows-focused library designed for deep OS-level stealth, it provides **full forensic parity** for Linux environments.

This means that BurnerNet's core "Ghost" engine—**Zero-Ghost Memory** (Heap/Stack wiping) and **Stack Isolation**—works identically on Linux. Your application remains resistant to memory dumpers and tracers in WSL or native Linux environments.

## Feature Support Matrix

| Feature | Linux Status | Benefit |
| :--- | :--- | :--- |
| **Zero-Ghost Memory** | ✅ Full Support | Automatically wipes URLs, Headers, and TLS keys from RAM. |
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

On Linux, BurnerNet uses standard `dlsym` resolution to hijack the internal memory functions of `libcurl` and `OpenSSL`.

**Note on OpenSSL 3.x:** On some Linux distributions, OpenSSL may perform its first internal allocation before BurnerNet can intercept it. BurnerNet still uses best-effort OpenSSL memory-hook registration and worker-thread cleanup, but Linux does not use the Windows bootstrap loader path. For the best results, create BurnerNet clients early in process startup and avoid long-lived transports for sensitive flows.

## Integration

To enable maximum hardening on Linux, ensure you use the following builder options:

```cpp
auto client = burner::net::ClientBuilder()
    .WithStackIsolation(true) // Enable Dynamic Analysis resistance
    .Build();
```

Notes:

- `InitializeNetworkingRuntime(...)` is a Windows bootstrap API and is not part of the normal Linux integration path.
- On Linux, focus on early client creation, short-lived transports, and application-owned trust decisions rather than Windows-specific loader controls.
