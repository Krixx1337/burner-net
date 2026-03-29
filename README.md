# BurnerNet

**Hardened C++20 networking for hostile environments.**

BurnerNet is a transport-layer hardening library for applications that cannot trust the local machine, process space, or network path. It is designed for desktop executables, injected DLLs, and security-critical tools where standard OS defaults such as proxies, DNS, and trust stores become attack surfaces.

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
- **Polymorphic binaries:** generated configs randomize `ErrorCode` values and `BURNERNET_ERROR_XOR`
- **Ephemeral secrets:** request material can be fetched via providers and wiped after use
- **Integrity hooks:** synchronous pre-flight, request, verification, and heartbeat hooks
- **Transport canary:** `SecurityAuditor` can detect local TLS interception paths
- **Dynamic hiding:** support for pre-loading renamed dependency DLLs with optional integrity verification

## Provisioning

BurnerNet is designed to be provisioned per project so each build can carry its own hardened constants.

1. Generate a config:

```bash
python tools/generate_config.py
```

This writes `BurnerNet_Config.h` into the current working directory with fresh `BURNERNET_ERROR_XOR`, `BURNERNET_SECURITY_SEED`, and randomized `ErrorCode` values.

2. Integrate it:

- CMake: `-DBURNERNET_USER_CONFIG_HEADER="BurnerNet_Config.h"`
- Visual Studio: add `BURNERNET_USER_CONFIG_HEADER="BurnerNet_Config.h"` to Preprocessor Definitions

The config template lives at [templates/BurnerNet_Config.example.h](templates/BurnerNet_Config.example.h).

## Minimal Example

```cpp
#include "burner/net/builder.h"

using namespace burner::net;

ErrorCode build_error = ErrorCode::None;
auto client = ClientBuilder()
    .WithApiVerification(true)
    .WithUseNativeCa(true)
    .Build(&build_error);
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
- [docs/USAGE_BEST_PRACTICES.md](docs/USAGE_BEST_PRACTICES.md)

## Build & Integration

BurnerNet requires C++20, CMake 3.21+, and libcurl.

- **Static linking:** recommended for the smallest attack surface. Link against `BurnerNet::BurnerNet` and use a static vcpkg triplet such as `x64-windows-static-md`.
- **Dynamic linking:** use `InitializeNetworkingRuntime(...)` to preload your networking stack from a custom directory and optionally enforce hash verification.

## Security Reality

BurnerNet is a hardening layer, not a silver bullet.

It is designed to raise the cost of attack and force attackers out of standard convenience tooling. It does not provide complete protection against a determined reverse engineer with administrative or kernel-level access.

- Keep critical decisions anchored on the server.
- Assume hostile clients can eventually patch local logic.
- Treat transport hardening, obfuscation, and integrity checks as delay and detection mechanisms, not absolute prevention.

BurnerNet is provided without any warranty of fitness for a particular security outcome. You are responsible for validating its tradeoffs against your threat model, deployment environment, and legal obligations.
