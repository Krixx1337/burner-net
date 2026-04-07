# BurnerNet

**Zero-trust anti-forensic networking. Wipes secrets. Severs traces. CPR in a Stealth Tank. 👻**

BurnerNet is a C++20 **anti-forensic networking engine**. It provides a fluent, CPR-like API for apps that cannot fully trust the local machine—physically wiping secrets from RAM and severing execution traces to hide your logic from scanners and debuggers.

It favors short-lived clients, explicit trust controls, import-light runtime options, and app-owned verification over convenience-first defaults.

Looking to protect the payloads downloaded by BurnerNet? Check out [RipStop Codec](https://github.com/Krixx1337/ripstop-codec) for in-memory asset descrambling.

[Principles](PRINCIPLES.md) • [Getting Started](#getting-started) • [Integration Paths](#integration-paths) • [Security Reality](#security-reality--the-white-box-defense)

## At a Glance

| Area | BurnerNet |
| :--- | :--- |
| **Language** | C++20 |
| **Platform** | Windows x64/x86 (**First-Class**), Linux (Verified) |
| **Transport** | `libcurl`-backed HTTP(S) |
| **Memory hygiene** | Secure wiping utilities and wiping allocators |
| **Forensic hygiene** | Automated heap/stack scrubbing across BurnerNet-managed transport state |
| **Dynamic Analysis** | Call stack isolation can sever the link between consumer and transport |
| **Build hardening** | Hardened error strings, obfuscated literals, reduced C++ runtime metadata in hardened builds |
| **Runtime hardening** | DoH support, provider-based secrets, and stricter trust controls |
| **Integration** | CMake or Visual Studio source-drop |

## Why Use It

Use BurnerNet when a normal HTTP client is too trusting for your environment.

It helps when you want to:
- keep request clients short-lived instead of sharing one global transport
- reduce reliance on local DNS and other host defaults
- fetch tokens, certs, and verification secrets only when needed
- keep response verification logic in your own application code
- reduce obvious plaintext strings and metadata in hardened builds

## Who It's For

BurnerNet fits projects such as:
- Windows desktop apps with high-value auth, licensing, or update requests
- embedded or injected code running in a host you do not fully trust
- tools that want stricter transport checks without giving up a fluent C++ API

## Standard Stack vs BurnerNet

| Concern | Typical HTTP stack | BurnerNet |
| :--- | :--- | :--- |
| **Client lifetime** | Often shared and long-lived | Designed for disposable clients and burst-scope use |
| **Sensitive values** | Secrets often sit in config or memory longer than needed | Provider callbacks fetch them close to use |
| **DNS and trust** | Usually inherits local resolver and host defaults | Supports stricter trust controls including DoH fallback and pinned keys |
| **Verification** | App-specific integrity checks are often bolted on later | Built to work with pre-flight, transport, and response verification hooks |

## Defensive Outcomes

- **Zero-Ghost Memory Architecture**: BurnerNet uses a custom **Prefix-Size Scrubber** to hook the internal memory allocation paths of `libcurl` and OpenSSL-backed flows. Sensitive transport buffers are wiped as they leave BurnerNet-managed lifetime. **This hygiene is verified on both Windows and Linux within the audited configurations described in the docs.**
- **Stack-Frame Swiping**: After every request, the library proactively scrubs its own thread stack (High-Water Mark scrubbing). This is intended to destroy ephemeral transport fragments before control returns to your application.
- **Moving-Target Heap**: The combination of disposable transports and aligned metadata headers creates high address-space dispersion, making the process memory unpredictable and resistant to stable pointer-mapping.
- **Short-lived request state**: BurnerNet is designed around disposable clients instead of process-wide singleton transports.
- **Less trust in the host**: DoH support, pinned-key support, and transport auditing help reduce dependence on compromised local defaults.
- **Lower plaintext exposure**: Provider callbacks and secure wiping utilities reduce the lifetime of certs, keys, tokens, and other sensitive buffers.
- **App-owned verification**: Response verification stays in your code through `WithResponseVerifier(...)` instead of being hardcoded into a shared library.
- **Harder static fingerprinting**: Release builds harden `ErrorCodeToString(...)` automatically, and compile-time literal obfuscation is available out of the box.
- **Import-light deployment options**: `BURNERNET_HARDEN_IMPORTS=1` can resolve runtime dependencies dynamically instead of advertising them directly in the import table, using BurnerNet's `KernelResolver` path on Windows.
- **Call Stack Isolation (Async Handoff)**: When enabled via `.WithStackIsolation(true)`, the library executes the transport lifecycle on a detached worker thread. This can physically sever the caller's call stack and reduce direct top-down tracing of application logic.

## Verified Stealth

BurnerNet does not just claim an import-light hardened mode; it also ships with audit notes for specific tested configurations. In a Windows x64 Release audit with `BURNERNET_HARDEN_IMPORTS=ON`:

- **IAT Blackout**: No entries for `libcurl.dll`, `ws2_32.dll`, `bcrypt.dll`, or `crypt32.dll` were observed in the audited binary.
- **Memory Dark-out**: Forensic scans (Cheat Engine "All Strings") failed to discover sensitive canary URLs or headers in the process heap or stack.
- **Debugger Blindness**: Integrated tests verify that the library triggers an "Identity Shift." The Decision-Maker (your app) and the Transporter (BurnerNet) operate on distinct Thread IDs, reducing top-down tracing during live debugging sessions.
- **Noise-to-Signal**: The library aims for forensic hygiene within its wipe authority, while acknowledging remaining system-level "shadows" in the OS and runtime environment.

Audit details and methodology:
- [docs/BINARY_STEALTH_AUDIT.md](docs/BINARY_STEALTH_AUDIT.md)

## Getting Started

Fastest path:
- Add BurnerNet to your build with CMake or Visual Studio source-drop.
- Build a client.
- Send a request.
- Destroy the client as soon as that request flow is done.

Minimal example:

```cpp
#include <iostream>

#include "burner/net/builder.h"
#include "burner/net/error.h"

int main() {
    auto build_result = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build();

    if (!build_result.Ok()) {
        std::cerr << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    const auto response = build_result.client
        ->Get("https://example.com")
        .WithHeader("Accept", "text/html")
        .WithTimeoutSeconds(10)
        .Send();

    if (!response.TransportOk()) {
        std::cerr << burner::net::ErrorCodeToString(response.transport_error) << '\n';
        return 1;
    }

    std::cout << "HTTP " << response.status_code << '\n';
    return 0;
}
```

For lower-trust utility traffic, BurnerNet also exposes a convenience preset:

```cpp
auto utility = burner::net::ClientBuilder()
    .WithCasualDefaults()
    .Build();
```

To sever the call stack between your application and the transport (stack isolation):

```cpp
auto build_result = burner::net::ClientBuilder()
    .WithUseNativeCa(true)
    .WithStackIsolation(true) // Sever the call stack from the consumer
    .Build();
```

## Integration Paths

### 1. Standard CMake

Use this when your downstream project already uses CMake and you want the cleanest dependency-managed path.

Docs:
- [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- [examples/cmake-consumer/README.md](examples/cmake-consumer/README.md)

### 2. Visual Studio Source-Drop

Use this when your environment is MSBuild-first or you want BurnerNet compiled directly inside your `.vcxproj`.

Docs:
- [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)
- [examples/vs-consumer/README.md](examples/vs-consumer/README.md)

### 3. Hardened Runtime Imports

Use this when you want to reduce obvious runtime dependency exposure and are prepared to manage bootstrap loading explicitly.

Enable:
- `BURNERNET_HARDEN_IMPORTS=1`
- Uses BurnerNet's `KernelResolver` path on Windows to support a more import-light runtime footprint

Reference:
- [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md)
- [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)

> **Linux Support:** BurnerNet provides full forensic parity (Memory Wiping & Stack Isolation) on Linux. See [docs/LINUX_USAGE.md](docs/LINUX_USAGE.md) for build instructions.

## Usage Notes

Recommended defaults:
- treat clients as disposable transports
- separate high-trust and lower-trust traffic into different clients
- use provider callbacks for mTLS material, bearer tokens, and response verification secrets
- keep business rules and trust anchors in your application

## Examples and Docs

Examples:
- [examples/01_basic_usage.cpp](examples/01_basic_usage.cpp)
- [examples/02_zero_trust_pipeline.cpp](examples/02_zero_trust_pipeline.cpp)
- [examples/03_custom_security_policy.cpp](examples/03_custom_security_policy.cpp)
- [examples/04_bootstrap_runtime.cpp](examples/04_bootstrap_runtime.cpp)
- [examples/05_mtls_usage.cpp](examples/05_mtls_usage.cpp)
- [examples/06_hmac_custom_verifier.cpp](examples/06_hmac_custom_verifier.cpp)

Documentation:
- [PRINCIPLES.md](PRINCIPLES.md)
- [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md)
- [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)
- [docs/LINUX_USAGE.md](docs/LINUX_USAGE.md)

## Requirements

- C++20
- Windows x64/x86 or Linux (GCC 13+ / Clang 15+)
- `libcurl` 7.87.0+ and `OpenSSL` headers
- **Linux Guide:** See [docs/LINUX_USAGE.md](docs/LINUX_USAGE.md)

## Security Reality & The White-Box Defense

BurnerNet is a hardening layer designed to raise the cost of attack to a professional level. We operate on the principle that **stealth should be architectural, not just superficial.**

**Can an attacker bypass BurnerNet if they have the source code?**
Knowledge of BurnerNet's source code is not, by itself, a master key to every downstream application. BurnerNet follows Kerckhoffs's Principle: the library is designed so that your app-specific trust anchors (HMAC secrets, pinned keys, UI logic, policy hooks) remain application-owned. Knowing the transport layer does not automatically yield a universal bypass of your specific security flow.

- **Stealth as a Delay:** Hardening forces attackers out of standard convenience tools and into tedious instruction-level analysis.
- **Data as the Root:** Use **Functional Dependency** (Principle 6) to ensure your app is literally broken without server-provided data.
- **The Ghost Advantage:** By the time an attacker finds your request logic, the **Stack Isolation** and **Memory Wiping** have already destroyed the forensic evidence they need.

