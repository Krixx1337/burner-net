# BurnerNet

**Hardened HTTP client with explicit trust controls and best-effort memory hygiene.**

BurnerNet is a C++20 HTTP client with a fluent, CPR-like API. It combines normal
TLS validation with application-owned response verification, dependency
integrity hooks, short-lived secret storage, and best-effort secure wiping.

It offers familiar host-compatible defaults for ordinary HTTP and an explicit Hardened profile for hostile environments. Both paths favor short-lived clients; advanced trust remains application-owned.

Looking to protect the payloads downloaded by BurnerNet? Check out [RipStop Codec](https://github.com/Krixx1337/ripstop-codec) for in-memory asset descrambling.

[Principles](PRINCIPLES.md) • [Getting Started](#getting-started) • [Integration Paths](#integration-paths) • [Security Reality](#security-reality--the-white-box-defense)

## At a Glance

| Area | BurnerNet |
| :--- | :--- |
| **Language** | C++20 |
| **Platform** | Windows x64/x86 (**First-Class**), Linux (Verified) |
| **Transport** | `libcurl`-backed HTTP(S) |
| **Memory hygiene** | Secure wiping utilities and wiping allocators |
| **Residue scope** | Explicit wiping across BurnerNet-managed transport state |
| **Dynamic Analysis** | Worker-thread handoff adds analysis friction; it is not a trust boundary |
| **Build hardening** | Optional diagnostic-string removal, obfuscated literals, reduced C++ runtime metadata in hardened builds |
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
| **Verification** | App-specific integrity checks are often bolted on later | Narrow request, peer, and response enforcement phases |

## Defensive Outcomes

- **Owned-memory wiping**: BurnerNet uses wiping containers and explicit response/credential scrubbing. Windows process-lifetime integrations can attempt Maximum Ghost mode to extend wiping into libcurl/OpenSSL allocations.
- **Bounded wipe authority**: Wiping reduces ordinary post-lifetime residue in memory BurnerNet owns. It does not prove that process, dependency, OS, register, or stack memory is clean.
- **Short-lived request state**: BurnerNet is designed around disposable clients instead of process-wide singleton transports.
- **Less trust in the host**: DoH support, pinned-key support, and exact transport errors help consumer-owned trust checks reduce dependence on compromised local defaults.
- **Lower plaintext exposure**: Provider callbacks and secure wiping utilities reduce the lifetime of certs, keys, tokens, and other sensitive buffers.
- **App-owned verification**: Response verification stays in your code through `WithResponseVerifier(...)` instead of being hardcoded into a shared library.
- **Harder static fingerprinting**: hardened builds can set `BURNERNET_DIAGNOSTIC_STRINGS=0` so `ErrorCodeToString(...)` returns stable `E<number>` values without embedding symbolic error names.
- **Import-light deployment options**: `BURNERNET_HARDEN_IMPORTS=1` can resolve runtime dependencies dynamically instead of advertising them directly in the import table, using BurnerNet's `KernelResolver` path on Windows.
- **Call Stack Isolation (Async Handoff)**: When enabled via `.WithStackIsolation(true)`, the library executes the transport lifecycle on a dedicated worker thread. This raises tracing cost but is not a trust boundary.

## Verified Stealth

BurnerNet ships point-in-time audit notes for specific tested configurations.
The recorded Windows x64 Release audit covers v1.0 with hardened imports and
the then-automatic global allocator injection:

- **IAT Blackout**: No entries for `libcurl.dll`, `ws2_32.dll`, `bcrypt.dll`, or `crypt32.dll` were observed in the audited binary.
- **Memory Dark-out**: Forensic scans (Cheat Engine "All Strings") failed to discover sensitive canary URLs or headers in the process heap or stack.
- **Debugger Blindness**: Integrated tests verify that the library triggers an "Identity Shift." The Decision-Maker (your app) and the Transporter (BurnerNet) operate on distinct Thread IDs, reducing top-down tracing during live debugging sessions.
- **Noise-to-Signal**: The library aims for forensic hygiene within its wipe authority, while acknowledging remaining system-level "shadows" in the OS and runtime environment.

Audit details and methodology:
- [docs/BINARY_STEALTH_AUDIT.md](docs/BINARY_STEALTH_AUDIT.md)

### Maximum Ghost mode

For a Windows executable or permanently loaded module, enable full backend
allocator wiping:

```bash
cmake -DBURNERNET_MAXIMUM_GHOST=ON
```

Call `InitializeNetworkingRuntime(...)` before creating clients to attempt early
hook installation. If another component already initialized libcurl/OpenSSL,
networking continues and `GlobalAllocatorHooksEnabled()` remains false. BurnerNet
retains its owning module and runtime only when installed callbacks require
process-lifetime ownership.

Keep this mode off for unloadable DLLs and plugins. Normal builds still wipe
BurnerNet-owned request, credential, response, and heap state, but do not claim
control over every internal libcurl/OpenSSL allocation.

## Getting Started

Fastest path:
- Add BurnerNet to your build with CMake or Visual Studio source-drop.
- Include `<burner/net.h>`.
- Create a stack client, send a request, then let it leave scope.

Minimal example:

```cpp
#include <iostream>

#include <burner/net.h>

int main() {
    burner::net::Client client;
    if (!client.IsReady()) {
        std::cerr << burner::net::ErrorCodeToString(client.InitError()) << '\n';
        return 1;
    }

    const auto response = client
        .Get("https://example.com")
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

`Client` uses Standard defaults: system CA, DNS, and proxy with TLS peer and hostname verification enabled. `WithCasualDefaults()` remains available as a Standard compatibility alias.

For security-critical traffic, use the Hardened profile. `Build()` rejects missing controls before any request:

```cpp
auto secure = burner::net::ClientBuilder(burner::net::ClientProfile::Hardened)
    .WithMtlsProvider(ProvideMtlsCredentials)
    .WithLoopbackPeerRejection()
    .WithConnectedPeerGuard(RejectUnexpectedPeer)
    .WithDnsFallback(burner::net::DnsMode::Doh,
                     "https://resolver.example/dns-query",
                     "Primary DoH",
                     "resolver.example:443:192.0.2.53")
    .AllowSystemDns(true) // explicit fallback, after DoH
    .WithResponseVerifier(VerifySignedResponse)
    .Build();
```

Hardened requires peer and hostname verification, stack isolation, DoH-first routing, and an app response verifier. SPKI pinning and loopback-peer rejection are opt-in. Loopback rejection runs after TLS but before HTTP bytes; it does not block the TLS/mTLS handshake. mTLS is provider-only. Connected-peer guards are optional defense-in-depth, not a replacement for TLS identity.

Provider callbacks are fail-closed: returning `false`, throwing, or returning enabled mTLS without both certificate and key material aborts before transport. Hardened DoH URLs must be non-empty `https://` URLs. Hardened redirects are unsupported in v1.3. A request cannot combine `OnChunkReceived(...)` with a response verifier because streamed bytes would escape before whole-response verification.

## Integration Paths

Normal consumers do not need to select security build flags:

```cmake
add_subdirectory(external/burner-net)
target_link_libraries(MyApp PRIVATE BurnerNet::BurnerNet)
```

BurnerNet defaults to string obfuscation with readable diagnostics, normal curl
linking, and unload-safe runtime ownership. Only set an advanced option when its
trade-off is required:

| Option | Use it when | Cost |
| :--- | :--- | :--- |
| `BURNERNET_DIAGNOSTIC_STRINGS=OFF` | Release binaries should omit readable error names | Logs contain stable numeric codes |
| `BURNERNET_HARDEN_IMPORTS=ON` | Windows dependency imports should be resolved through bootstrap | Explicit early runtime loading |
| `BURNERNET_MAXIMUM_GHOST=ON` | A process-lifetime Windows integration needs libcurl/OpenSSL allocator wiping | BurnerNet and hooked runtimes cannot unload |

`BURNERNET_OBFUSCATE_STRINGS` is an advanced build/debug control. It defaults
on and ordinary consumers should leave it unchanged.

Hardened imports require a dedicated runtime directory, a complete
`dependency_dlls` manifest, and an `integrity_provider`. Bootstrap validates and
locks every packaged DLL before loading any module. Dependency lookup is limited
to that DLL's directory and System32; BurnerNet does not mutate process-wide
user DLL search directories.

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

### 4. Maximum Ghost Runtime

Use this Windows-only build mode when backend memory wiping matters more than
module unload. It is independent from the Hardened client profile and can be
combined with normal or hardened imports.

> **Linux Support:** BurnerNet supports owned-memory wiping and stack isolation
> on Linux. Maximum Ghost allocator interception is Windows-only in v1.3. See
> [docs/LINUX_USAGE.md](docs/LINUX_USAGE.md).

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
- [examples/03_connected_peer_guard.cpp](examples/03_connected_peer_guard.cpp)
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

BurnerNet is a transport-hardening layer. Its real security properties come
from TLS verification, application response proof, loader integrity, and
explicit bounds—not from hiding how the library works.

**Can an attacker bypass BurnerNet if they have the source code?**
Knowledge of BurnerNet's source code is not, by itself, a master key to every downstream application. BurnerNet follows Kerckhoffs's Principle: app-specific trust anchors, response proof, UI logic, and narrow guards remain application-owned. Knowing transport layer does not automatically yield a universal bypass of a specific security flow.

- **Analysis friction:** Obfuscation, hidden imports, and worker-thread handoff
  can slow basic inspection, but do not stop a capable in-process attacker.
- **Data as the Root:** Use **Functional Dependency** (Principle 6) to ensure your app is literally broken without server-provided data.
- **Bounded hygiene:** Wiping shortens the lifetime of selected owned buffers.
  Copies may remain in dependencies, the OS, registers, stacks, crash dumps, or
  attacker-controlled snapshots.

