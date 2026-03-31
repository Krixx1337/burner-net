# BurnerNet

**Hardened C++20 networking for hostile environments.**

BurnerNet is a Windows-focused C++20 networking library for apps that cannot fully trust the local machine or network. It is built for security-sensitive request flows where default OS behavior like system DNS, proxies, and long-lived plaintext buffers can become attack surfaces.

It favors short-lived clients, explicit trust controls, import-light runtime options, and app-owned verification over convenience-first defaults.

Looking to protect the payloads downloaded by BurnerNet? Check out [RipStop Codec](https://github.com/Krixx1337/ripstop-codec) for in-memory asset descrambling.

[Principles](PRINCIPLES.md) • [Getting Started](#getting-started) • [Integration Paths](#integration-paths) • [Security Reality](#security-reality)

## At a Glance

| Area | BurnerNet |
| :--- | :--- |
| **Language** | C++20 |
| **Platform** | Windows x64/x86 |
| **Transport** | `libcurl`-backed HTTP(S) |
| **Memory hygiene** | Secure wiping utilities and wiping allocators |
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

- **Short-lived request state**: BurnerNet is designed around disposable clients instead of process-wide singleton transports.
- **Less trust in the host**: DoH support, pinned-key support, and transport auditing help reduce dependence on compromised local defaults.
- **Lower plaintext exposure**: Provider callbacks and secure wiping utilities reduce the lifetime of certs, keys, tokens, and other sensitive buffers.
- **App-owned verification**: Response verification stays in your code through `WithResponseVerifier(...)` instead of being hardcoded into a shared library.
- **Harder static fingerprinting**: Release builds harden `ErrorCodeToString(...)` automatically, and compile-time literal obfuscation is available out of the box.
- **Import-light deployment options**: `BURNERNET_HARDEN_IMPORTS=1` can resolve runtime dependencies dynamically instead of advertising them directly in the import table, using BurnerNet's `KernelResolver` path on Windows.

## Verified Stealth

BurnerNet does not just claim an import-light hardened mode. The repository includes a binary audit for a Windows x64 release build using bootstrap runtime loading with `BURNERNET_HARDEN_IMPORTS=ON`.

In the documented audit, the hardened binary showed:
- no `libcurl.dll` or `ws2_32.dll` entries in the Import Address Table
- no `bcrypt.dll` or `crypt32.dll` entries in the Import Address Table
- no plaintext HTTP verbs, protocol strings, or core security error names in the audited strings dump

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

## Usage Notes

Recommended defaults:
- treat clients as disposable transports
- separate high-trust and lower-trust traffic into different clients
- use provider callbacks for mTLS material, bearer tokens, and response verification secrets
- keep business rules and trust anchors in your application

For deeper guidance, see:
- [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md)
- [examples/02_zero_trust_pipeline.cpp](examples/02_zero_trust_pipeline.cpp)
- [examples/03_custom_security_policy.cpp](examples/03_custom_security_policy.cpp)
- [examples/05_mtls_usage.cpp](examples/05_mtls_usage.cpp)
- [examples/06_hmac_custom_verifier.cpp](examples/06_hmac_custom_verifier.cpp)

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

## Requirements

- C++20
- Windows x64/x86
- `libcurl`

## Security Reality

BurnerNet is a hardening layer, not a silver bullet.

It is designed to raise the cost of attack and force attackers out of standard convenience tooling. It does not provide complete protection against a determined reverse engineer with administrative or kernel-level access.

- Keep critical decisions anchored on the server.
- Assume hostile clients can eventually patch local logic.
- Treat transport hardening, obfuscation, and integrity checks as delay and detection mechanisms, not absolute prevention.
- Validate the tradeoffs against your own threat model, deployment environment, and legal obligations.

C++20 • Windows x64/x86 • MIT
