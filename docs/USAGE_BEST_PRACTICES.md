# BurnerNet Usage Best Practices

This guide shows recommended usage patterns for short-lived secrets and mixed security levels (public + login APIs).

## 1. Treat clients as disposable transports
- Prefer request-scope or burst-scope clients: create, use, destroy.
- Avoid process-wide singletons, global clients, and long-lived member-held transports for sensitive paths.
- Rebuild the client when policy changes instead of mutating transport state over time.

Why:
- A short-lived client is a smaller target for pointer hooks and memory inspection.
- Provider callbacks get invoked close to use, then temporary buffers are wiped and the transport object dies shortly after.
- The library is intentionally optimized for hostile environments, not for long-lived shared-state ergonomics.

Recommended pattern:
```cpp
#include "burner/net/builder.h"

void FetchLoginTicket() {
    burner::net::ErrorCode build_error = burner::net::ErrorCode::None;
    auto client = burner::net::ClientBuilder()
        .WithPinnedKey("sha256//BASE64_PIN_GOES_HERE")
        .WithBearerTokenProvider(&ProvideBearer)
        .Build(&build_error);

    if (client == nullptr) {
        return;
    }

    auto response = client->Post("https://api.example.com/login")
        .WithBody(R"({\"hwid\":\"...\"})")
        .Send();

    // `client` falls out of scope here and the transport is destroyed immediately.
}
```

Avoid:
```cpp
class ApiService {
public:
    std::unique_ptr<burner::net::FluentClient> client;
};
```

## 2. Split clients by trust level
- Use one client for public/simple endpoints (no mTLS/signature).
- Use one client for auth/login endpoints (mTLS + optional response signature verifier).

Why:
- Avoid accidentally sending certs/tokens to endpoints that do not need them.
- Keep policy explicit and easy to review.

Recommended traffic lanes:
- Use a paranoid client for auth, licenses, logic seeds, and any request that must resist local interception or spoofing.
- Use a utility client for logs, crash uploads, public metadata, or other lower-trust flows where system DNS and system proxy behavior are acceptable.
- Do not mix these lanes through one long-lived client object. Separate clients keep transport handles and behavior distinct.

Example utility lane:
```cpp
auto utility = burner::net::ClientBuilder()
    .WithCasualDefaults()
    .Build();
```

## 3. Prefer provider callbacks for sensitive values
- Use `ClientConfig::mtls_provider` for cert/key/password.
- Use `ClientConfig::bearer_token_provider` for access token.
- Use `SignatureVerifierConfig::secret_provider` for signature secret.
- Use `ClientConfig::on_before_request`, `on_request_heartbeat`, and `on_response_received` for synchronous integrity checks around the transport lifecycle.

Avoid long-lived plaintext in:
- global variables
- static strings
- config structs persisted for process lifetime

## 4. Example: secure client with short-lived providers
```cpp
#include "burner/net/http.h"
#include "burner/net/signature_verifier.h"

static bool ProvideMtls(burner::net::MtlsCredentials& out) {
    // App-specific source: skCrypt, DPAPI, vault, remote seed, etc.
    std::string cert = LoadCertPemShortLived();
    std::string key = LoadKeyPemShortLived();
    std::string pwd = LoadKeyPwdShortLived();

    out.enabled = true;
    out.cert_pem = cert;
    out.key_pem = key;
    out.key_password = pwd;
    return true;
}

static bool ProvideSigSecret(std::string& out) {
    out = LoadSignatureSecretShortLived();
    return !out.empty();
}

static bool ProvideBearer(std::string& out) {
    out = LoadBearerTokenShortLived();
    return !out.empty();
}

void BuildSecureClient() {
    burner::net::ClientConfig cfg{};
    cfg.verify_peer = true;
    cfg.verify_host = true;
    cfg.use_native_ca = true;
    cfg.mtls_provider = &ProvideMtls;
    cfg.bearer_token_provider = &ProvideBearer;
    cfg.response_verifier = std::make_shared<burner::net::HmacSha256HeaderVerifier>(
        burner::net::SignatureVerifierConfig{
            .signature_header = "X-Auth-Verify",
            .secret_provider = &ProvideSigSecret
        });

    auto created = burner::net::CreateHttpClient(cfg);
    if (!created.Ok()) {
        // map opaque error code to app-specific UX
        return;
    }

    burner::net::HttpRequest req{};
    req.method = burner::net::HttpMethod::Post;
    req.url = "https://api.example.com/login";
    req.body = R"({\"hwid\":\"...\"})";
    req.max_body_bytes = 512 * 1024; // 512 KiB cap for login API responses
    req.retry.max_attempts = 2;
    req.dns_fallback.enabled = true;
    req.dns_fallback.strategies = {
        {burner::net::DnsMode::Doh, "Cloudflare DoH (Strict)", "https://1.1.1.1/dns-query"},
        {burner::net::DnsMode::Doh, "Cloudflare DoH (Strict Secondary)", "https://1.0.0.1/dns-query"},
        {burner::net::DnsMode::System, "System DNS Insecure", ""}
    };

    auto response = created.client->Send(req);
}
```

## 5. Example: public client (no mTLS/signature)
```cpp
burner::net::ClientConfig cfg{};
cfg.verify_peer = true;
cfg.verify_host = true;
cfg.response_verifier = nullptr;
cfg.mtls.enabled = false;

auto created = burner::net::CreateHttpClient(cfg);
```

## 6. Host bootstrap templates

### `.exe` host
```cpp
burner::net::BootstrapConfig boot{};
boot.link_mode = burner::net::LinkMode::Dynamic;
boot.dependency_directory = LR"(C:\MyApp\bin)";
boot.integrity_policy.enabled = true;
boot.integrity_policy.fail_closed = true;
// `dependency_dlls` defaults follow the current process architecture and debug/release mode.
// Match the allowlist entries to the actual DLL names in your packaged redist folder.
boot.integrity_policy.sha256_allowlist = {
    {boot.dependency_dlls[0], "PUT_SHA256_HEX_HERE"},
    {boot.dependency_dlls[1], "PUT_SHA256_HEX_HERE"},
    {boot.dependency_dlls[2], "PUT_SHA256_HEX_HERE"},
    {boot.dependency_dlls[3], "PUT_SHA256_HEX_HERE"}
};
auto init = burner::net::InitializeNetworkingRuntime(boot);
```

### injected `.dll` host
```cpp
// Do not initialize heavy networking inside DllMain.
// Defer to a worker/init thread, then call:
burner::net::BootstrapConfig boot{};
boot.link_mode = burner::net::LinkMode::Dynamic;
boot.dependency_directory = LR"(C:\Games\Guild Wars 2\addons\kxvision)";
auto init = burner::net::InitializeNetworkingRuntime(boot);
```

## 7. Dependency integrity policy (dynamic mode)
- Integrity checks happen once per dependency, immediately before `LoadLibraryExW`.
- If allowlist hash mismatches and `fail_closed=true`, bootstrap fails.
- Keep hashes in app code (policy), not in shared library code.
- Recompute hashes when you upgrade runtime DLLs.
- Ensure `dependency_directory` is not writable by standard users; prefer app-owned folder with strict ACLs.

## 8. Response body limits
- Use `HttpRequest::max_body_bytes` for endpoints that should never return large payloads.
- Keep `0` only for trusted/internal endpoints where unlimited buffering is acceptable.
- In integration coverage, pass `--tiny-body-limit` to force the cap path and verify expected transport failure.

## 9. Redirect and header safety
- Keep `follow_redirects=false` for auth/login requests.
- If authorization headers/token are present and redirects are enabled, the client blocks the request by design.
- Header names/values with CR/LF are rejected to prevent header injection.

## 10. Recommended defaults
- Release builds harden `ErrorCodeToString(...)` automatically when `NDEBUG` is defined.
- Debug builds keep symbolic error names by default for easier local diagnosis.
- BurnerNet includes a built-in compile-time literal obfuscator by default.
- Treat `ErrorCode::TlsVerificationFailed` and `ErrorCode::TransportVerificationFailed` as distinct trust failures, not generic connectivity errors.
- Keep login/business logic in app code, not inside `BurnerNet`.
- Prefer one disposable HTTP client instance per worker/thread or burst of requests.
- Prefer separate client instances for paranoid and utility traffic instead of toggling one client back and forth.
- Keep transport integrity hooks synchronous and fail closed by returning `false`.

## 11. CI recommendation for redist
- Build the example or test targets in CI so CMake stages the runtime set into `out/build/<preset>/bin/redist`.
- Treat missing runtime DLLs in that generated `redist` folder as a build failure.
- Run that check separately for each dynamic triplet you ship (`x64-windows`, `x86-windows`).

## 12. Startup canary
- For high-risk paths, run `burner::net::SecurityAuditor::CheckTransportIntegrity(client->Raw())` during startup or before auth.
- A `true` result means the transport rejected the `expired.badssl.com` canary exactly as expected.
- A `false` result means the environment is compromised or inconclusive; fail closed for sensitive flows.

## 13. Defeating Local DNS Hijacking & API Spoofing

**The Threat:** In hostile environments such as compromised machines or game modding contexts, attackers often use PowerShell scripts, local DNS overrides, or `hosts` file modifications to redirect your API domains to a malicious server. They may then supply a valid or locally-trusted TLS certificate and return spoofed `200 OK` responses to bypass auth checks or feed malicious data to your application.

**Why mTLS and custom plaintext DNS fail here:**
- mTLS protects the server from unauthorized clients, not the client from a spoofed server. If the fake server does not require a client certificate, a standard HTTP client can still connect.
- Hardcoding a DNS server over plaintext UDP/53 can still be intercepted by local firewall rules, WFP drivers, or other privileged hooks.
- Public key pinning is often too brittle when you rely on CDNs such as Cloudflare that rotate edge certificates.

**The BurnerNet Solution:**
To secure your app without assuming stable CDN certificates, combine **DNS over HTTPS (DoH)** with **application-layer response signatures (HMAC)**.

1. **DoH** bypasses the compromised OS DNS resolver and encrypts the lookup.
2. **HMAC signatures** ensure that even if an attacker intercepts traffic and presents a trusted TLS certificate, they still cannot forge a valid response payload without the shared secret.

```cpp
#include <memory>

#include "burner/net/builder.h"
#include "burner/net/signature_verifier.h"

bool ProvideSigSecret(std::string& out);

auto client = burner::net::ClientBuilder()
    // 1. Bypass OS DNS spoofing via encrypted DoH
    .WithDnsFallback(
        burner::net::DnsMode::Doh,
        "https://1.1.1.1/dns-query",
        "Cloudflare DoH (Strict)")

    // 2. Cryptographically prove the server generated the payload
    .WithResponseVerifier(std::make_shared<burner::net::HmacSha256HeaderVerifier>(
        burner::net::SignatureVerifierConfig{
            .signature_header = "X-Auth-Verify",
            .secret_provider = &ProvideSigSecret
        }))
    .Build();
```

If an attacker spoofs the API, `HmacSha256HeaderVerifier` returns a signature verification error and the untrusted payload is rejected instead of being handed to app logic.

## 14. Managing Strict DoH (DNS-over-HTTPS)
By default, BurnerNet is **Strict DoH-First**. It bypasses the OS DNS resolver by communicating directly with IP-based DoH endpoints such as `https://1.1.1.1/dns-query`. This defeats local `hosts` edits, PowerShell DNS hijacking, and straightforward resolver hooks.

If the network blocks those DoH endpoints, BurnerNet fails closed by default. If you want to trade security for availability, you must explicitly opt into the OS resolver:

```cpp
auto client = burner::net::ClientBuilder()
    .AllowSystemDns(true) // Explicitly permits fallback to the easily hijacked OS DNS
    .Build();
```

## 15. Binary Uniqueness (Polymorphism)
BurnerNet now derives its hardened error XOR key from compile-time state automatically, so each build gets a distinct numeric error surface without a generator step. Literal obfuscation is also built in by default.

If you want to mount project-specific security hooks, define your policy type and make it visible while BurnerNet compiles:

```cpp
#define BURNERNET_SECURITY_POLICY MyProject::SecurityPolicy
```

For source-drop integrations, `BURNERNET_SECURITY_POLICY_HEADER` can force-include the header that declares that type.

Typical `OnVerifyTransport` policy:

```cpp
// AppSecurity.h
#pragma once

#include <string>
#include <string_view>

namespace my_app {

struct SecurityPolicy {
    static inline bool OnVerifyTransport(const char* url, const char* remote_ip) {
        (void)url;
        return remote_ip != nullptr && std::string_view(remote_ip) != "127.0.0.1";
    }

    static inline void OnPreRequest(burner::net::HttpRequest&) {}
    static inline void OnSignatureVerified(bool, burner::net::ErrorCode) {}
    static inline void OnTamper() {}
    static inline void OnError(burner::net::ErrorCode, const char*) {}
    static inline std::string GetUserAgent() { return ""; }
};

} // namespace my_app

#define BURNERNET_SECURITY_POLICY ::my_app::SecurityPolicy
```

Do not include `burner/net/http.h` or `burner/net/error.h` from that policy header. BurnerNet injects the policy header before those headers are fully defined, and the hook signatures already rely on forward declarations provided by BurnerNet.

Build integration example:

```cmake
target_include_directories(BurnerNet PRIVATE ${CMAKE_SOURCE_DIR}/app)
target_compile_definitions(BurnerNet PRIVATE BURNERNET_SECURITY_POLICY_HEADER=\"AppSecurity.h\")
```

Visual Studio integration:
- Add the folder containing `AppSecurity.h` to Additional Include Directories for the BurnerNet project.
- Add `BURNERNET_SECURITY_POLICY_HEADER="AppSecurity.h"` to the BurnerNet project's Preprocessor Definitions.

Important:
- The hook policy is compiled into BurnerNet itself.
- Defining `BURNERNET_SECURITY_POLICY` only in your application target does nothing if BurnerNet is already prebuilt.
- `OnVerifyTransport` runs after curl reports the remote IP and should return `false` to fail closed with `ErrorCode::TransportVerificationFailed`.

## 16. 32-bit and 64-bit Windows builds

- BurnerNet supports both x64 and x86 Windows client builds.
- Match the process architecture to the runtime dependencies exactly: a 32-bit process must load 32-bit `libcurl.dll`, and a 64-bit process must load 64-bit `libcurl.dll`.
- `x64-debug` / `x64-release` use `x64-windows`
- `x64-debug-static` / `x64-release-static` use `x64-windows-static-md`
- `x86-debug` / `x86-release` use `x86-windows`
- `x86-debug-static` / `x86-release-static` use `x86-windows-static-md`
- `InitializeNetworkingRuntime(...)` is only needed for dynamic triplets. Static triplets should keep `BootstrapConfig::link_mode = LinkMode::Static` or skip bootstrap entirely.
- If you preload runtime DLLs with `InitializeNetworkingRuntime(...)`, keep separate `redist/` layouts for x86 and x64 so you never cross-load the wrong binary set.
