# The BurnerNet Principles: Paranoid Networking

Modern C++ networking libraries (like `cpr` or `libcurl`) are designed for **convenience and compatibility**. They assume a "Friendly Host" environment where the user, the Operating System, and the local network are all trusted actors.

**BurnerNet is different.**

It is designed for **Hostile Environments** such as game modding, injected DLLs, and security-critical automation, where the local environment cannot be trusted. We operate on six core pillars: **Zero-Trust Networking**, **Ephemeral Memory**, a **Stringless Core**, **Bring Your Own Weapons**, **Disposable Transports**, **Functional Dependency**, and the **White-Box Defense**.

---

## 1. Zero-Trust Networking (Verified Server and Response)
Standard clients trust the Windows Certificate Store and the System Proxy. An attacker with Fiddler or a custom Root CA can intercept and decrypt this traffic effortlessly.

*   **Proxy Blackholing:** BurnerNet ignores system proxies by default. Traffic is forced directly to the edge, bypassing local interception tools.
*   **Certificate Pinning:** We do not trust the OS to validate certificates. We support Public Key Pinning to ensure you are talking to *your* server, and no one else.
*   **Explicit Secure DNS:** The OS DNS resolver is treated as compromised. BurnerNet does not bake public DoH endpoints into the default client state; you opt into strict DNS-over-HTTPS targets explicitly so those resolver choices live in your application, not in every BurnerNet binary.
*   **TLS Hardening:** We enforce modern TLS 1.2+ protocols and secure cipher suites, preventing downgrade attacks.

## 2. Ephemeral Memory (Short-Lived Secrets)
If a secret exists in memory for more than a few milliseconds, it is a target for memory dumpers and scanners.

*   **Provider Pattern:** Secrets (Tokens, Keys, Certs) are never stored in long-lived configuration structs. They are fetched via callbacks nanoseconds before they are needed.
*   **Aggressive Wiping:** Every temporary buffer used for sensitive data is scrubbed using `SecureZeroMemory` immediately after use.

## 3. Stringless Core (No Plaintext Breadcrumbs or Magic Numbers)
Plaintext strings and cryptographic "magic numbers" are the fingerprints of security logic. A reverse engineer does not need to understand your whole binary if a `strings` dump, a domain search, or a `FindCrypt` pass already reveals where the trust decisions live.

*   **Dark Core Architecture:** BurnerNet aims to be a ghost library. The core binary avoids shipping hardcoded cryptographic implementations, public DoH endpoint lists, and universal canary domains that would otherwise act as signatures across every downstream build.
*   **Opaque Error Codes:** The library emits no plaintext error strings in hardened mode. It operates exclusively on a strictly typed `enum class ErrorCode`, and `ErrorCodeToString(...)` collapses to a numeric/XORed representation by default.
*   **Signature-Free Infrastructure:** Verification algorithms, transport canary targets, and bootstrap integrity checks live in application callbacks rather than inside BurnerNet itself. That keeps the transport layer agnostic and denies attackers an obvious universal bypass point.
*   **Protocol Stealth:** Essential internal strings that must exist for transport behavior are stack-obfuscated and wiped after use so a naïve static dump reveals as little as possible.
*   **Source-Drop Advantage (Recommended):** The preferred integration model is to compile BurnerNet's source directly inside the host project. That keeps setup simple and lets compile-time hardening be instantiated inside each downstream build instead of being frozen into one shared prebuilt library artifact.
*   **Import-Light Runtime:** On Windows, BurnerNet uses its own `KernelResolver` for hidden API resolution in the hardened path, keeping that trust root inside the library instead of depending on a third-party importer.

## 4. Bring Your Own Weapons (The Dark Mounts)
Anti-Reverse Engineering (Anti-RE) is a cat-and-mouse game. BurnerNet is a **Professional Hardening** library, not an aggressive obfuscator: it avoids heavy control-flow tricks, spaghetti-code transforms, and source-hostile obfuscation. We target the sweet spot between **Security**, **Maintainability**, and **Performance** by shipping welded mounts while leaving the weapons to the application.

*   **No Spaghetti-Code Obfuscation:** We reject techniques like control-flow flattening or MBA that turn source code into an unmaintainable mess. BurnerNet's stealth is structural: clean C++20 design choices that still produce a dark binary.
*   **Algorithm Agnostic:** We do not hardcode one signature scheme or verification routine. Response verification is mounted through lambda-based hooks so you can inject HMAC, Ed25519, custom checksums, or any application-specific proof you want.
*   **Parametric Auditing:** We do not ship a default transport canary. You provide your own TLS-failure targets and audit behavior, which keeps each binary's trust checks specific to the application instead of to BurnerNet.
*   **Zero-Dependency Bootstrap:** Runtime integrity decisions are delegated to user-provided callbacks. BurnerNet loads and validates dependency paths, but the application decides what "trusted" means.
*   **Woven Logic:** Policy hooks are compiled into the transport path through concrete types, concepts, and hardened dispatch rather than standard virtual inheritance. That keeps the source auditable while making those checks harder to unplug at runtime.
*   **Respect for the Developer:** We provide the armor: hidden imports, mangled pointers, vtable-free dispatch, and safe mount points. You provide the weapons: debugger detection, VM heuristics, integrity scans, trust anchors, and application-specific enforcement.

## 5. Disposable Transports (Short-Lived Clients)
Standard networking libraries optimize for long-lived clients, shared connection pools, and process-wide singletons. In a hostile environment, that pattern creates a stationary target.

*   **Attack Surface in Time:** A client that stays alive for the life of the process gives attackers a stable object to inspect, hook, and patch.
*   **Burst-and-Burn Lifecycle:** BurnerNet is designed around short-lived transports: create a client, send the request, and destroy it as soon as the burst of traffic is complete.
*   **Moving Target Defense:** Recreating transport handles and re-fetching secrets through providers on each burst forces an attacker to re-establish timing and hooks repeatedly.
*   **Simpler Trust Boundaries:** Disposable clients keep ownership local to the request path and avoid the false promise of shared, mutable, thread-safe state.

## 6. Functional Dependency (No Hollow Shells)
We acknowledge a hard truth: **A dedicated reverse engineer with enough time will bypass any local check.** If your security relies on a single `if (is_authenticated)` block, your application is a hollow shell that can be cracked with a single byte patch.

*   **Anti-RE is not the Goal:** BurnerNet does not claim to stop reverse engineering; it aims to make the *results* of reverse engineering less useful.
*   **The Hollow Shell Problem:** We discourage using the library only for "Yes/No" authentication. If an attacker can patch a jump instruction to bypass your login, the transport layer has failed its purpose.
*   **Broken-by-Design:** Real security requires that the application is **literally broken** without server-provided data. Use BurnerNet to fetch critical logic seeds, encrypted constants, or configuration offsets that are required for the application to run.
*   **Data-Driven Integrity:** By using a response verifier, you ensure that the server-provided "Brains" of your app have not been spoofed by a local proxy. If the signature is wrong, the data is discarded, and the app remains a non-functional shell.

---

### The Vision: The Ghost Library (Dark Core)
The goal of BurnerNet is to provide a **Fortified Transport Layer** that behaves like a ghost within your application:

1. **Security (The Dark Core):** No universal crypto signatures, no baked-in third-party endpoints, and no default canary domains. Every compiled instance can carry different trust logic and is harder to classify with static analysis.
2. **Maintainability (The Clean Source):** Clean, idiomatic C++20 source code that remains easy to audit, debug, and extend even though the resulting machine code stays intentionally sparse and unhelpful to attackers.
3. **Independence (The Final Boss):** A transport layer that does not trust the OS, the local network, or even its own defaults. Trust decisions are explicit and application-owned.

**We provide the armor; you provide the soul.**

By staying in the category of **Professional Hardening**, BurnerNet remains a reliable high-performance tool for legitimate developers while still presenting a dark, expensive target for attackers. The library secures the transport path, strips out universal signatures where practical, and leaves the final trust anchors in the host application where they belong.

---

## 7. The White-Box Defense (Kerckhoffs's Principle)
A common concern with open-source security tools is the "Universal Bypass": if an attacker knows the source code, can they write a single script to crack every application using the library?

**BurnerNet is designed to avoid a simple universal bypass.** We follow Kerckhoffs's Principle: the system should remain defensible even if everything about it is public knowledge, so long as the "key" (your application's specific trust anchors) remains secret.

### Why Knowledge of the Source is not a Master Key:
*   **Compile-Time Polymorphism:** BurnerNet uses `__COUNTER__` and `__TIME__` seeds to randomize internal XOR keys and obfuscation constants. Two different applications using the same BurnerNet source code will produce fundamentally different machine code. An attacker cannot use a universal byte-pattern signature to find your security logic.
*   **Vtable-Free Dispatch:** We avoid standard C++ `virtual` methods for sensitive callbacks. By using custom type-erasure and `EncodedPointer` mangling, we eliminate the predictable "vftables" that attackers usually target for memory redirection/hooking.
*   **Transport Inlining:** When integrated via the recommended Source-Drop path, the C++ compiler can merge BurnerNet code directly into your application's business logic. The boundary between "The Library" and "The App" becomes less obvious in the final assembly.
*   **Decoupled Trust:** BurnerNet provides the *mechanism* (The Mount), but you provide the *logic* (The Weapon). An attacker who reverses your app's specific HMAC routine or Certificate Pin gains zero knowledge that helps them crack another BurnerNet-powered application.

Knowledge of the source code allows an attacker to understand **how** we hide, but it does not tell them **where** you are hidden or **what** secrets you are carrying.
