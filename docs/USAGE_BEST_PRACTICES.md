# BurnerNet v1.3 Usage Best Practices

## Standard and Hardened

Standard suits ordinary HTTP traffic. Hardened suits auth, licensing, signed
configuration, and other hostile-host paths.

```cpp
auto utility = burner::net::ClientBuilder()
    .WithCasualDefaults()
    .Build();
```

Hardened requires TLS peer/host verification, stack isolation, DoH-first DNS,
and an application response verifier:

```cpp
using namespace burner::net;

auto secure = ClientBuilder(ClientProfile::Hardened)
    .WithDnsFallback(
        DnsMode::Doh,
        "https://resolver.example/dns-query",
        "Primary DoH",
        "resolver.example:443:192.0.2.53")
    .AllowSystemDns(true)
    .WithResponseVerifier(
        [](const HttpRequest&, const HttpResponseView& response) {
            return VerificationResult{
                VerifySignedResponse(response)
                    ? ErrorCode::None
                    : ErrorCode::SigMismatch};
        })
    .Build();
```

`WithPinnedKey(...)` remains optional for endpoints whose applications control
key rotation. Avoid pinning CDN-managed endpoints such as Cloudflare unless the
deployment has an explicit, tested overlap-and-rotation process. Hardened
rejects redirects before providers or networking run.

## Narrow callbacks

```cpp
auto client = burner::net::ClientBuilder()
    .WithRequestGuard([](const burner::net::HttpRequest& request) {
        return request.url.starts_with("https://");
    })
    .WithLoopbackPeerRejection()
    .WithConnectedPeerGuard([](const burner::net::ConnectedPeer& peer) {
        return peer.remote_port == 443;
    })
    .WithTransferCancellation([](const burner::net::TransferProgress&) {
        return !ApplicationIsShuttingDown();
    })
    .Build();
```

- Request guard runs once on caller thread before any provider or socket effect.
- Credential providers run once per physical attempt on transport thread.
- Built-in loopback rejection runs after TLS and before a custom peer guard.
- Connected-peer guard runs after TLS, before HTTP bytes, on transport thread.
- Transfer cancellation may run many times on transport thread.
- Response verifier runs once on caller thread after isolated worker joins.

Callbacks are client-owned. Do not retain callback-scoped views. Synchronize
captured external state. Do not call one client concurrently from multiple
threads.

`WithLoopbackPeerRejection()` is opt-in in both profiles. It rejects IPv4
`127.0.0.0/8`, IPv6 `::1`, mapped/compatible loopback forms, and invalid peer
identity. It does not reject LAN/private ranges. Because libcurl's prereq phase
runs after TLS, this prevents HTTP credentials, headers, and body from reaching
loopback; it does not prevent the TCP/TLS or mTLS handshake. True pre-connect
address enforcement remains deferred to v2.

## Short-lived secrets

```cpp
auto client = burner::net::ClientBuilder()
    .WithMtlsProvider([](burner::net::MtlsCredentials& out) {
        out.enabled = true;
        out.cert_pem = LoadCertificate();
        out.key_pem = LoadPrivateKey();
        return !out.cert_pem.empty() && !out.key_pem.empty();
    })
    .WithBearerTokenProvider([](burner::net::DarkString& out) {
        out = LoadToken();
        return !out.empty();
    })
    .Build();
```

Persistent mTLS configuration was removed. Prefer disposable clients: build,
send a small burst, destroy.

## Verification and publication

`VerificationStatus` is sole verification truth:

```cpp
const auto response = client.client->Get(url).Send();
if (!response.TransportOk()) {
    HandleTransportFailure(response.transport_error);
} else if (!response.WasResponseVerified()) {
    HandleVerificationFailure(response.verification_error);
} else {
    Consume(response.body);
}
```

Verifier failure wipes body, headers, telemetry, and DNS-strategy details before
return. `OnChunkReceived(...)` cannot be combined with response verification
because streamed bytes are published immediately.

## Redirects, retry, and DNS fallback

- Hardened redirects are unsupported in v1.3.
- Standard rejects redirects when a bearer provider, mTLS provider, or response
  verifier is configured.
- Security and callback failures are terminal.
- Only transient DNS, connect, timeout, and configured HTTP 5xx outcomes retry.
- System DNS fallback must be explicit and follows DoH in Hardened.

## Bootstrap

```cpp
burner::net::BootstrapConfig boot{};
boot.link_mode = burner::net::LinkMode::Dynamic;
boot.dependency_directory = runtime_dir;
boot.dependency_dlls = {L"libcurl.dll", L"libcrypto-3-x64.dll"};
boot.dependency_directory_guard =
    [](const std::filesystem::path& canonical_dir) {
        return IsApprovedRuntimeDirectory(canonical_dir);
    };
boot.integrity_provider =
    [](const std::filesystem::path& path, const std::wstring& basename) {
        return VerifyPackagedDependency(path, basename);
    };
```

Provider absence means no application integrity check. Provider presence means
every dependency must pass; `false` and exceptions fail closed.

Process-global allocator hooks are a build contract, not runtime policy. Enable
`BURNERNET_MAXIMUM_GHOST=1` only when BurnerNet's owning module may remain
loaded until process exit. In that build, call `InitializeNetworkingRuntime`
before creating clients; hook failure is terminal and shutdown preserves the
hooked runtime.

## v1.3 migration

| Removed or renamed | v1.3 replacement |
| --- | --- |
| `WithSecurityPolicy(...)` | narrow phase callback(s) |
| `WithPreFlight(...)` | `WithRequestGuard(...)` |
| `WithTransportCheck(...)` | `WithConnectedPeerGuard(...)` |
| `WithHeartbeat(...)` | `WithTransferCancellation(...)` |
| environment/tamper/observer callbacks | consumer application logic |
| `WithMtls(MtlsCredentials)` | `WithMtlsProvider(...)` |
| verifier `bool` plus `ErrorCode*` | `VerificationResult` |
| `HttpResponse::verified` | `WasResponseVerified()` / `verification_status` |
| bootstrap `SecurityPolicy` | `dependency_directory_guard` |
| `DependencyIntegrityPolicy` switches | direct `integrity_provider` |
| `install_global_allocator_hooks` | build with `BURNERNET_MAXIMUM_GHOST=1` |

No deprecated aliases remain. This avoids duplicate authority and makes v2
migration cleaner.

## Security posture

Keep audit logging, debugger response, telemetry interpretation, and process
actions in the consumer. Keep response cryptography application-owned. Make
runtime behavior depend on verified server-provided data rather than a patchable
local success flag.
