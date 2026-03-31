# BurnerNet Usage Best Practices

This guide shows recommended usage patterns for short-lived secrets and mixed security levels (public + login APIs).

## 1. Choose your integration path
- Prefer CMake when your downstream project already uses CMake.
- Prefer Visual Studio source-drop when your downstream project is MSBuild-first.
- Use bootstrap runtime loading only for custom runtime DLL redist scenarios.

Why:
- Compiling BurnerNet inside your own build re-instantiates compile-time obfuscation and hardened error-string generation.
- This is a hardening advantage, not a cryptographic identity guarantee. Do not treat build-time polymorphism as a substitute for server-side secrets or response verification.
- CMake is the cleanest dependency-managed path, but `.vcxproj` source-drop is also viable when your environment is anchored to MSBuild.

Integration guides:
- CMake: [CMAKE_INTEGRATION.md](CMAKE_INTEGRATION.md)
- Visual Studio `.vcxproj`: [VISUAL_STUDIO_INTEGRATION.md](VISUAL_STUDIO_INTEGRATION.md)

## 2. Treat clients as disposable transports
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
    auto client = burner::net::ClientBuilder()
        .WithPinnedKey("sha256//BASE64_PIN_GOES_HERE")
        .WithBearerTokenProvider(&ProvideBearer)
        .Build();

    if (client.client == nullptr) {
        return;
    }

    auto response = client.client->Post("https://api.example.com/login")
        .WithBody(R"({\"hwid\":\"...\"})")
        .Send();

    // `client` falls out of scope here and the transport is destroyed immediately.
}
```

Avoid:
```cpp
class ApiService {
public:
    std::unique_ptr<burner::net::FluentClient<burner::net::CurlHttpClient>> client;
};
```

## 3. Split clients by trust level
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

## 4. Prefer provider callbacks for sensitive values
- Use `ClientConfig::mtls_provider` for cert/key/password.
- Use `ClientConfig::bearer_token_provider` for access token.
- Use a `ResponseVerifyFn` lambda or callable to fetch signature material only when verification runs.
- Use `ClientBuilder::WithPreFlight(...)`, `WithEnvironmentCheck(...)`, `WithTransportCheck(...)`, `WithHeartbeat(...)`, and `WithResponseReceived(...)` for synchronous integrity checks around the transport lifecycle when you do not need a full custom `ISecurityPolicy`.
- If you do need a full policy, implement `ISecurityPolicy` and pass it with `WithSecurityPolicy(...)`.

Avoid long-lived plaintext in:
- global variables
- static strings
- config structs persisted for process lifetime

## 5. Example: secure client with short-lived providers
```cpp
#include "burner/net/builder.h"

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

static bool ProvideBearer(std::string& out) {
    out = LoadBearerTokenShortLived();
    return !out.empty();
}

void BuildSecureClient() {
    auto created = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .WithMtlsProvider(&ProvideMtls)
        .WithBearerTokenProvider(&ProvideBearer)
        .WithResponseVerifier(
            [](const burner::net::HttpRequest&, const burner::net::HttpResponse& response, burner::net::ErrorCode* reason) {
                std::string secret = LoadSignatureSecretShortLived();
                if (secret.empty()) {
                    if (reason != nullptr) {
                        *reason = burner::net::ErrorCode::SigEmpty;
                    }
                    return false;
                }

                // App-owned verification logic lives here.
                const bool ok = VerifyResponseHmac(response, secret);
                burner::net::SecureWipe(secret);
                if (!ok && reason != nullptr) {
                    *reason = burner::net::ErrorCode::SigMismatch;
                }
                return ok;
            })
        .Build();

    if (!created.Ok()) {
        // map opaque error code to app-specific UX
        return;
    }

    auto response = created.client->Post("https://api.example.com/login")
        .WithBody(R"({\"hwid\":\"...\"})")
        .WithTimeoutSeconds(15)
        .Send();
}
```

Gold-standard reference:
- See [../examples/05_mtls_usage.cpp](../examples/05_mtls_usage.cpp) for the provider-driven mTLS pattern that keeps client certs and keys out of long-lived config state.
- See [../examples/06_hmac_custom_verifier.cpp](../examples/06_hmac_custom_verifier.cpp) for an app-owned HMAC verifier built outside BurnerNet core.

## 6. Example: public client (no mTLS/signature)
```cpp
burner::net::ClientConfig cfg{};
cfg.verify_peer = true;
cfg.verify_host = true;
cfg.response_verifier = {};
cfg.mtls.enabled = false;

auto created = burner::net::CreateHttpClient(cfg);
```

## 7. Host bootstrap templates

### `.exe` host
```cpp
burner::net::BootstrapConfig boot{};
boot.link_mode = burner::net::LinkMode::Dynamic;
boot.dependency_directory = LR"(C:\MyApp\bin)";
boot.integrity_policy.enabled = true;
boot.integrity_policy.fail_closed = true;
boot.integrity_policy.integrity_provider =
    [](const std::filesystem::path& dll_path, const std::wstring& dll_name) {
        return VerifyPackagedRuntimeDll(dll_path, dll_name);
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

## 8. Dependency integrity policy (dynamic mode)
- Integrity checks happen once per dependency, immediately before `LoadLibraryExW`.
- If your callback returns `false` and `fail_closed=true`, bootstrap fails.
- Keep hashes or signature verification in app code, not in shared library code.
- Recompute any expected hashes or signatures when you upgrade runtime DLLs.
- Ensure `dependency_directory` is not writable by standard users; prefer app-owned folder with strict ACLs.

## 9. Response body limits
- Use `HttpRequest::max_body_bytes` for endpoints that should never return large payloads.
- Keep `0` only for trusted/internal endpoints where unlimited buffering is acceptable.
- In integration coverage, pass `--tiny-body-limit` to force the cap path and verify expected transport failure.

## 10. Redirect and header safety
- Keep `follow_redirects=false` for auth/login requests.
- If authorization headers/token are present and redirects are enabled, the client blocks the request by design.
- Header names/values with CR/LF are rejected to prevent header injection.

## 11. Recommended defaults
- Release builds harden `ErrorCodeToString(...)` automatically when `NDEBUG` is defined.
- Debug builds keep symbolic error names by default for easier local diagnosis.
- BurnerNet includes a built-in compile-time literal obfuscator by default.
- Prefer Source-Drop integration when you want that compile-time hardening to be instantiated inside your own app build.
- Treat `ErrorCode::TlsVerificationFailed` and `ErrorCode::TransportVerificationFailed` as distinct trust failures, not generic connectivity errors.
- Keep login/business logic in app code, not inside `BurnerNet`.
- Prefer one disposable HTTP client instance per worker/thread or burst of requests.
- Prefer separate client instances for paranoid and utility traffic instead of toggling one client back and forth.
- Keep transport integrity hooks synchronous and fail closed by returning `false`.

## 12. CI recommendation for redist
- Build the example or test targets in CI so CMake stages the runtime set into `out/build/<preset>/bin/redist`.
- Treat missing runtime DLLs in that generated `redist` folder as a build failure.
- Run that check separately for each dynamic triplet you ship (`x64-windows`, `x86-windows`).

## 13. Startup canary
- For high-risk paths, run `burner::net::SecurityAuditor::CheckTransportIntegrity(client->Raw(), canary_urls)` during startup or before auth. If the audit fails, BurnerNet now forwards that result into `ISecurityPolicy::OnTamper()`.
- A `true` result means the transport rejected each app-owned TLS-failure canary exactly as expected.
- A `false` result means the environment is compromised or inconclusive; fail closed for sensitive flows.

## 14. Defeating Local DNS Hijacking & API Spoofing

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
#include "burner/net/builder.h"

auto client = burner::net::ClientBuilder()
    // 1. Bypass OS DNS spoofing via encrypted DoH
    .WithDnsFallback(
        burner::net::DnsMode::Doh,
        "https://resolver.example/dns-query",
        "DoH Custom")

    // 2. Cryptographically prove the server generated the payload
    .WithResponseVerifier(
        [](const burner::net::HttpRequest&, const burner::net::HttpResponse& response, burner::net::ErrorCode* reason) {
            std::string secret = LoadSignatureSecretShortLived();
            const bool ok = VerifyResponseHmac(response, secret);
            burner::net::SecureWipe(secret);
            if (!ok && reason != nullptr) {
                *reason = burner::net::ErrorCode::SigMismatch;
            }
            return ok;
        })
    .Build();
```

If an attacker spoofs the API, your app-owned verifier returns a signature verification error and the untrusted payload is rejected instead of being handed to app logic.

## 14. Managing Strict DoH (DNS-over-HTTPS)
BurnerNet does not bake any public DoH endpoints into the default client state. Configure your own endpoint with `WithDnsFallback(DnsMode::Doh, "...", "...")` so resolver indicators remain app-owned.

If the network blocks those DoH endpoints, BurnerNet fails closed by default. If you want to trade security for availability, you must explicitly opt into the OS resolver:

```cpp
auto client = burner::net::ClientBuilder()
    .WithDnsFallback(
        burner::net::DnsMode::Doh,
        "https://resolver.example/dns-query",
        "DoH Custom")
    .AllowSystemDns(true) // Explicitly permits fallback to the easily hijacked OS DNS
    .Build();
```

## 15. Binary Uniqueness (Polymorphism)
BurnerNet now derives its hardened error XOR key from compile-time state automatically, so each build gets a distinct numeric error surface without a generator step. Literal obfuscation is also built in by default.

If you want project-specific security hooks without rebuilding BurnerNet, derive from `burner::net::ISecurityPolicy` and pass the instance into the builder:

```cpp
class SecurityPolicy final : public burner::net::ISecurityPolicy {
public:
    bool OnVerifyTransport(const char* url, const char* remote_ip) const override {
        (void)url;
        return remote_ip != nullptr && std::string_view(remote_ip) != "127.0.0.1";
    }

    std::string GetUserAgent() const override {
        return "MyApp/1.0";
    }
};

auto client = burner::net::ClientBuilder()
    .WithSecurityPolicy(SecurityPolicy{})
    .Build();
```

Important:
- If you do not provide a policy, BurnerNet automatically uses `DefaultSecurityPolicy`.
- The policy lives in application code and works with prebuilt BurnerNet libraries.
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
