# BurnerNet

**Hardened C++20 networking for hostile environments.**

BurnerNet is a transport-layer hardening library for applications that cannot trust the local machine, process space, or network path. It is designed for desktop executables, injected DLLs, and security-critical tools where standard OS defaults such as proxies, DNS, and trust stores become attack surfaces.

Looking to protect the payloads downloaded by BurnerNet? Check out [RipStop Codec](https://github.com/Krixx1337/ripstop-codec) for in-memory asset descrambling.

[Principles](PRINCIPLES.md) • [Provisioning](#provisioning) • [Features](#features) • [Security Reality](#security-reality)

## Overview

Most networking libraries optimize for convenience. BurnerNet optimizes for defensive posture.

It is built for:
- Windows x64/x86 applications with high-value request paths
- injected or embedded code that cannot fully trust the host environment
- short-lived, disposable transports instead of long-lived shared clients

## Features

- **Zero-trust transport:** direct HTTPS-focused behavior with strict redirect and header validation
- **Encrypted DNS:** DNS-over-HTTPS support to reduce dependence on hostile local resolution
- **Polymorphic builds:** hardened error strings pick up a compile-time XOR key automatically
- **Built-in literal obfuscation:** internal security-anchor strings are masked at compile time out of the box
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

Error strings are hardened by default. Define `BURNERNET_LEAK_STRINGS_FOR_DEBUGGING` only when you explicitly want plaintext debug strings.

For custom security hooks, derive from `burner::net::ISecurityPolicy` and pass the instance into `ClientBuilder::WithSecurityPolicy(...)`. The fluent `WithBeforeRequest(...)`, `WithPreFlight(...)`, `WithHeartbeat(...)`, `WithResponseReceived(...)`, and `WithPostVerification(...)` helpers now feed the default runtime policy wrapper instead of bypassing it. See [examples/04_custom_security_policy.cpp](examples/04_custom_security_policy.cpp) and [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md).

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

See also:
- [examples/01_basic_usage.cpp](examples/01_basic_usage.cpp)
- [examples/02_security_audit.cpp](examples/02_security_audit.cpp)
- [examples/03_traffic_lanes.cpp](examples/03_traffic_lanes.cpp)
- [examples/04_custom_security_policy.cpp](examples/04_custom_security_policy.cpp)
- [docs/CMAKE_INTEGRATION.md](docs/CMAKE_INTEGRATION.md)
- [docs/VISUAL_STUDIO_INTEGRATION.md](docs/VISUAL_STUDIO_INTEGRATION.md)
- [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md)

## Build & Integration

BurnerNet requires C++20 and libcurl.

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
