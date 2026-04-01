# BurnerNet on Linux

While BurnerNet is a Windows-focused library designed for deep OS-level stealth, it provides **full forensic parity** for Linux environments.

This means that BurnerNet's core "Ghost" engine—**Zero-Ghost Memory** (Heap/Stack wiping) and **Stack Isolation**—works identically on Linux. Your application remains resistant to memory dumpers and tracers in WSL or native Linux environments.

## Feature Support Matrix

| Feature | Linux Status | Benefit |
| :--- | :--- | :--- |
| **Zero-Ghost Memory** | ✅ Full Support | Automatically wipes URLs, Headers, and TLS keys from RAM. |
| **Stack Isolation** | ✅ Full Support | Severs the call stack to hide your app logic from tracers. |
| **String Obfuscation** | ✅ Full Support | URLs and security strings are encrypted at compile-time. |
| **Hardened Imports** | ✅ Supported | Removes libcurl/OpenSSL symbols from the ELF import table. |
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

**Note on OpenSSL 3.x:** On some Linux distributions, OpenSSL may perform its first internal allocation before BurnerNet can intercept it. For the best forensic results, always call `InitializeNetworkingRuntime` as the very first line of your `main()` function.

## Integration

To enable maximum hardening on Linux, ensure you use the following builder options:

```cpp
auto client = burner::net::ClientBuilder()
    .WithStackIsolation(true) // Enable Dynamic Analysis resistance
    .Build();
```
