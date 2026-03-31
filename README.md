# BurnerNet

**Hardened C++20 networking for hostile environments.**

BurnerNet is a transport-layer hardening library for applications that cannot trust the local machine, process space, or network path. It is designed for desktop executables, injected DLLs, and security-critical tools where standard OS defaults such as proxies, DNS, and trust stores become attack surfaces.

The library is currently Windows-centric.

Looking to protect the payloads downloaded by BurnerNet? Check out [RipStop Codec](https://github.com/Krixx1337/ripstop-codec) for in-memory asset descrambling.

[Principles](PRINCIPLES.md) • [Provisioning](#provisioning) • [Features](#features) • [Security Reality](#security-reality)

## Overview

Most networking libraries optimize for convenience. BurnerNet optimizes for defensive posture.

Think of BurnerNet as **"CPR in a Tank"**: it gives you a modern, fluent C++20 API, but wraps it in a heavier-duty shell built for hostile environments.

It is built for:
- Windows x64/x86 applications with high-value request paths
- injected or embedded code that cannot fully trust the host environment
- short-lived, disposable transports instead of long-lived shared clients

## Features

- **Zero-trust transport:** direct HTTPS-focused behavior with strict redirect and header validation
- **Zero-copy payloads:** `body_view` support for high-performance, non-owning request bodies without duplicating plaintext buffers
- **Resource protection:** transfer progress callbacks can monitor download/upload totals and abort oversized or suspicious transfers mid-stream
- **Encrypted DNS:** DNS-over-HTTPS support to reduce dependence on hostile local resolution
- **Polymorphic builds:** hardened error strings pick up a compile-time XOR key automatically
- **Built-in literal obfuscation:** internal security-anchor strings are masked at compile time out of the box
- **Import-light Windows path:** `lazy_importer` is vendored and used for hidden Windows and cURL API resolution
- **Ephemeral secrets:** request material can be fetched via providers and wiped after use
- **Integrity hooks:** synchronous pre-flight, request, verification, and heartbeat hooks
- **Transport canary:** `SecurityAuditor` can detect local TLS interception paths
- **Dynamic hiding:** support for pre-loading renamed dependency DLLs with optional integrity verification

## Provisioning

BurnerNet now builds without a generator step.

Recommended integration:
- use CMake and link `BurnerNet::BurnerNet`

Alternative integration:
- use Visual Studio `.vcxproj` source-drop when your environment is MSBuild-first

For the actual setup details, see:
- [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)

Error strings are hardened by default. `ErrorCodeToString(...)` returns a numeric/XORed string unless you explicitly opt into plaintext debugging with `BURNERNET_LEAK_STRINGS_FOR_DEBUGGING`.

For custom security hooks, pass a concrete policy type into `ClientBuilder::WithSecurityPolicy(...)`. The easiest path is to derive from `ISecurityPolicy` so the unchanged hooks inherit sensible defaults, but the runtime path still avoids virtual dispatch because `ISecurityPolicy` has no virtual methods. The fluent `WithPreFlight(...)`, `WithEnvironmentCheck(...)`, `WithTransportCheck(...)`, `WithHeartbeat(...)`, `WithResponseReceived(...)`, and `WithPostVerification(...)` helpers layer on top of that policy instead of replacing it. `WithHeartbeat(...)` receives transfer progress stats so policies can enforce resource limits during the active transfer. See [examples/03_custom_security_policy.cpp](examples/03_custom_security_policy.cpp) and [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md).

## Minimal Example

```cpp
#include "burner/net/builder.h"

using namespace burner::net;

auto result = ClientBuilder().Build();
if (!result.client) {
    auto build_error = result.error;
}
```

For lower-trust utility traffic:

```cpp
auto utility = burner::net::ClientBuilder()
    .WithCasualDefaults()
    .Build();
```

Hook order on the request path:
- `OnVerifyEnvironment()` during `Build()`
- `OnPreRequest()` before each attempt
- `OnHeartbeat(TransferProgress)` from the active transfer callback
- `OnVerifyTransport()` after the connection is established
- `OnResponseReceived()` after a successful transfer
- `OnSignatureVerified()` after response verification when enabled
- `OnTamper()` when an integrity check fails closed

See also:
- [examples/01_basic_usage.cpp](examples/01_basic_usage.cpp)
- [examples/02_zero_trust_pipeline.cpp](examples/02_zero_trust_pipeline.cpp)
- [examples/03_custom_security_policy.cpp](examples/03_custom_security_policy.cpp)
- [examples/04_bootstrap_runtime.cpp](examples/04_bootstrap_runtime.cpp)
- [examples/05_mtls_usage.cpp](examples/05_mtls_usage.cpp)
- [examples/06_hmac_custom_verifier.cpp](examples/06_hmac_custom_verifier.cpp)
- [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)
- [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md)

## Build & Integration

BurnerNet requires C++20 and libcurl.

The repository includes `lazy_importer` as a vendored header under [include/burner/net/external/lazy_importer/lazy_importer.hpp](include/burner/net/external/lazy_importer/lazy_importer.hpp). Downstream users do not need to fetch it separately.

Integration guides:
- CMake consumers: [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- Visual Studio `.vcxproj` consumers: [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)

## Security Reality

BurnerNet is a hardening layer, not a silver bullet.

It is designed to raise the cost of attack and force attackers out of standard convenience tooling. It does not provide complete protection against a determined reverse engineer with administrative or kernel-level access.

- Keep critical decisions anchored on the server.
- Assume hostile clients can eventually patch local logic.
- Treat transport hardening, obfuscation, and integrity checks as delay and detection mechanisms, not absolute prevention.

BurnerNet is provided without any warranty of fitness for a particular security outcome. You are responsible for validating its tradeoffs against your threat model, deployment environment, and legal obligations.
