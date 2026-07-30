# The BurnerNet Principles: Paranoid Networking

Modern C++ networking libraries such as `cpr` and `libcurl` are designed for
convenience and compatibility. BurnerNet supports that adoption path through
its Standard profile while keeping a separate Hardened contract for
applications that treat the host as hostile.

**BurnerNet is different.**

Standard uses normal host networking behavior with TLS peer and hostname
verification. Hardened removes implicit trust, requires explicit structural
controls, and fails closed. We operate on seven core pillars:
**Zero-Trust Networking**, **Ephemeral Memory**, a **Stringless Core**,
**Bring Your Own Weapons**, **Disposable Transports**,
**Functional Dependency**, and the **White-Box Defense**.

---

## 1. Zero-Trust Networking (Verified Server and Response)

Standard intentionally behaves like a familiar HTTP client. Applications
facing a hostile host must explicitly select `ClientProfile::Hardened`.

- **Proxy Blackholing:** Hardened disables system proxy use. Standard preserves
  host proxy behavior for ordinary desktop, VPN, and enterprise environments.
- **Explicit Secure DNS:** Hardened requires at least one application-selected
  HTTPS DoH strategy. System DNS is allowed only as an explicit fallback after
  DoH. BurnerNet bakes no public resolver endpoints into default state.
- **TLS Verification:** Both profiles enable peer and hostname verification.
  Hardened refuses to build if either is disabled and enforces TLS 1.2 or newer.
- **Application Response Proof:** Hardened requires an application-owned
  response verifier. Transport data remains staged inside BurnerNet until that
  verifier passes. Failed verification wipes body, headers, telemetry, and DNS
  details before returning.
- **Optional Pinning:** `WithPinnedKey(...)` remains available for applications
  that control their server-key lifecycle. It is not required. Pinning
  CDN-managed endpoints such as Cloudflare can create outages during legitimate
  rotation and should be avoided without an explicit overlap strategy.
- **Peer Guard:** `WithConnectedPeerGuard(...)` may reject a connected address
  after TLS and before HTTP request bytes. It is defense-in-depth, not a
  replacement for TLS identity.
- **Opt-In Loopback Rejection:** `WithLoopbackPeerRejection()` performs
  allocation-free binary IPv4/IPv6 classification before the custom peer guard.
  It blocks HTTP data, not the earlier TLS/mTLS handshake. Pre-connect address
  enforcement remains a v2 concern.
- **Redirect Containment:** Hardened forbids redirects. Standard rejects
  redirects when credentials or response verification could cross origin
  without an explicit per-hop trust model.
- **Terminal Security Failures:** Guard rejection, credential failure,
  callback failure, TLS or configured-pin failure, cancellation, size-limit
  failure, and response-verification failure never trigger retry or DNS
  fallback.

## 2. Ephemeral Memory (Short-Lived Secrets)

If a secret exists in memory, it is a target for memory dumpers and scanners.
BurnerNet minimizes exposure time and residue rather than claiming that live
process memory can be made invisible.

- **Provider Pattern:** `WithMtlsProvider(...)` and
  `WithBearerTokenProvider(...)` acquire credentials close to use. Persistent
  mTLS credentials are not part of the v1.3 client API.
- **Request-Scoped Secrets:** Ephemeral tokens belong to the request that uses
  them, not to global or long-lived coordination state.
- **Aggressive Wiping:** Sensitive request, credential, response, header, retry,
  and bootstrap buffers use wiping storage or explicit secure wiping.
- **Wipe Before Reuse:** Failed, abandoned, and superseded responses are wiped
  before fallback, retry, or publication.
- **Bounded Publication:** Streaming exposes bytes immediately and therefore
  cannot be combined with whole-response verification. Authenticated streaming
  requires a future chunk-verification design.

Wiping reduces forensic residue. It cannot defeat a privileged observer reading
a secret while that secret is actively in use.

## 3. Stringless Core (No Plaintext Breadcrumbs or Magic Numbers)

Plaintext strings and recognizable cryptographic constants are fingerprints of
security logic. A reverse engineer should not gain a universal map of every
BurnerNet consumer from a simple strings dump.

- **Dark Core Architecture:** The core avoids hardcoded signature algorithms,
  public DoH endpoint lists, universal canary domains, and application trust
  anchors.
- **Selectable Diagnostics:** Readable symbolic errors are the developer
  default. `BURNERNET_DIAGNOSTIC_STRINGS=0` removes that table and returns
  stable `E<number>` identifiers. `ErrorCode` numeric values remain explicit.
- **Signature-Free Infrastructure:** Response cryptography, transport canaries,
  environment checks, and dependency-integrity decisions belong to application
  callbacks rather than a universal security auditor inside BurnerNet.
- **Protocol Stealth:** Essential internal literals are obfuscated where
  practical and temporary decoded values are wiped after use.
- **Source-Drop Advantage:** Compiling BurnerNet directly into the consumer is
  the preferred hostile-environment integration. It keeps setup simple and
  allows per-build hardening to be instantiated within the host binary.
- **Import-Light Runtime:** Hardened Windows paths use encoded, dynamically
  resolved platform and curl entry points where this adds resistance without
  making source ownership obscure.

These techniques raise analysis cost. They are not cryptographic trust anchors.

## 4. Bring Your Own Weapons (Narrow Security Mounts)

Anti-reverse engineering is a cat-and-mouse game. BurnerNet is a professional
hardening library, not an aggressive obfuscator. It rejects source-hostile
control-flow tricks and exposes small application-owned enforcement points.

- **No Spaghetti-Code Obfuscation:** Maintainable C++20 and auditable ordering
  take priority over opaque control flow, MBA transforms, and fake branches.
- **One Owner per Phase:** v1.3 has one callback path for each retained phase:
  request guard, credential acquisition, connected-peer guard, transfer
  cancellation, and response verification. There is no parallel
  `SecurityPolicy` facade.
- **Observers Are Not Enforcement:** Telemetry and audit callbacks do not decide
  whether transport succeeds. Consumers inspect returned diagnostics after the
  transport has enforced its own invariants.
- **Algorithm Agnostic:** The response verifier can host HMAC, Ed25519, a custom
  proof, or another application-specific scheme. BurnerNet owns phase ordering
  and fail-closed publication, not the cryptographic policy.
- **Narrow Bootstrap:** BurnerNet canonicalizes dependency paths, rejects
  reparse-point ambiguity, revalidates file identity around loading, and offers
  `dependency_directory_guard` and `integrity_provider` callbacks. Application
  callbacks never run while the global bootstrap mutex is held.
- **Maximum Ghost Build Contract:** Process-global curl/OpenSSL allocator hooks
  default off. Windows process-lifetime consumers enable
  `BURNERNET_MAXIMUM_GHOST=1`; BurnerNet then fails closed unless hooks install
  before backend use and retains their owning code until process exit.
- **Respect for the Developer:** BurnerNet provides hidden imports, encoded
  pointers, vtable-free callback storage, deterministic sequencing, wiping, and
  safe mount points. The application provides debugger policy, VM heuristics,
  trust anchors, integrity rules, and user-facing recovery.

Callback ownership and lifetime are explicit. Consumer exceptions are converted
to stable failures and never cross a libcurl C callback, isolated worker
entrypoint, bootstrap callback boundary, or public BurnerNet boundary.

## 5. Disposable Transports (Short-Lived Clients)

Long-lived clients, shared mutable pools, and process-wide security state create
stationary targets.

- **Attack Surface in Time:** A client that remains alive for the process
  lifetime gives attackers a stable object to inspect, hook, and patch.
- **Burst-and-Burn Lifecycle:** BurnerNet favors creating a client for a bounded
  traffic burst and destroying it when that work is complete.
- **Moving-Target Defense:** Recreating transport handles and reacquiring
  credentials forces an attacker to re-establish timing and observation points.
- **Simple Ownership:** Clients are single-owner objects. Concurrent `Send()`
  calls on one client are not supported. Local ownership is easier to reason
  about than hidden shared coordination.

## 6. Functional Dependency (No Hollow Shells)

A dedicated reverse engineer with enough time can bypass a local check. If
security depends on one `if (is_authenticated)` branch, the application is a
hollow shell that can be cracked with one patch.

- **Anti-RE Is Not the Goal:** BurnerNet makes the results of reverse
  engineering less useful; it does not claim to prevent analysis.
- **Reject the Hollow Shell:** Do not use networking only to retrieve a Boolean
  that unlocks otherwise complete local functionality.
- **Broken by Design:** Important behavior should depend on verified
  server-provided data: entitlement patterns, encrypted configuration,
  short-lived material, or other data the client cannot synthesize locally.
- **Data-Driven Integrity:** Response verification protects that functional data
  from local proxy substitution. Failed proof publishes no usable response
  payload.
- **No Central Trusted Flag:** `VerificationStatus` reports one fact about the
  response. It must not become universal authority for unrelated application
  behavior.

---

### The Vision: The Ghost Library (Dark Core)

BurnerNet is a fortified transport layer that behaves like a ghost inside its
consumer:

1. **Security (The Dark Core):** No universal crypto implementation, baked-in
   resolver list, default canary domain, or application trust anchor.
2. **Maintainability (The Clean Source):** Clean, direct C++20 with explicit
   ownership, deterministic phase ordering, and one source of truth.
3. **Independence (The Final Boss):** Hardened rejects implicit proxy, DNS, and
   response trust. Standard remains available when compatibility is the correct
   tradeoff.

**We provide the armor; you provide the soul.**

Professional hardening means making real controls independent and maintainable,
not multiplying fake checks merely to inflate patch count.

---

## 7. The White-Box Defense (Kerckhoffs's Principle)

Knowing BurnerNet's source must not reveal one universal application trust key
or one policy object whose patch bypasses every consumer.

- **Per-Build Variation:** Compile-time seeds vary encoded constants and pointer
  representations between builds, frustrating naïve fixed-byte signatures.
  This is variation, not cryptographic secrecy.
- **Vtable-Free Dispatch:** Narrow callbacks use custom type erasure and encoded
  invocation pointers instead of a predictable virtual security-policy table.
- **Distinct Enforcement Effects:** Request validation, native TLS identity,
  optional peer rejection, optional pinning, application response proof,
  wipe-before-publication, and consumer functional dependency occur at distinct
  points. No shared `trusted` flag controls them all.
- **Transport Inlining:** Source-drop integration lets compiler optimization
  blend transport mechanics into consumer code, reducing the value of one
  prebuilt-library signature.
- **Decoupled Trust:** BurnerNet provides mechanisms; each consumer supplies its
  own endpoints, response proof, credentials, bootstrap integrity, and
  functional-data dependency.

Knowledge of the source explains the mechanisms. It does not reveal the
consumer's secrets or replace server-provided functional data.

## Security Limit

Pointer encoding, literal obfuscation, hidden imports, stack isolation, wiping,
and source-drop builds raise attacker cost. They cannot make a client immune to
a dedicated attacker who controls its process. Real security comes from normal
TLS validation, application response proof, minimal secret lifetime, independent
enforcement effects, and functionality that genuinely depends on verified
server data.
