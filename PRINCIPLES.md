# The BurnerNet Principles: Paranoid Networking

Modern C++ networking libraries (like `cpr` or `libcurl`) are designed for **convenience and compatibility**. They assume a "Friendly Host" environment where the user, the Operating System, and the local network are all trusted actors.

**BurnerNet is different.**

It is designed for **Hostile Environments** such as game modding, injected DLLs, and security-critical automation, where the local environment cannot be trusted. We operate on six core pillars: **Zero-Trust Networking**, **Ephemeral Memory**, a **Stringless Core**, **Bring Your Own Weapons**, **Disposable Transports**, and **Functional Dependency**.

---

## 1. Zero-Trust Networking (Verified Server and Response)
Standard clients trust the Windows Certificate Store and the System Proxy. An attacker with Fiddler or a custom Root CA can intercept and decrypt this traffic effortlessly.

*   **Proxy Blackholing:** BurnerNet ignores system proxies by default. Traffic is forced directly to the edge, bypassing local interception tools.
*   **Certificate Pinning:** We do not trust the OS to validate certificates. We support Public Key Pinning to ensure you are talking to *your* server, and no one else.
*   **Strict DoH-First DNS:** The OS DNS resolver is treated as compromised. BurnerNet defaults to IP-based DNS-over-HTTPS endpoints, bypassing local DNS poisoning, `hosts` overrides, and `getaddrinfo` hooks unless you explicitly opt back into System DNS.
*   **TLS Hardening:** We enforce modern TLS 1.2+ protocols and secure cipher suites, preventing downgrade attacks.

## 2. Ephemeral Memory (Short-Lived Secrets)
If a secret exists in memory for more than a few milliseconds, it is a target for memory dumpers and scanners.

*   **Provider Pattern:** Secrets (Tokens, Keys, Certs) are never stored in long-lived configuration structs. They are fetched via callbacks nanoseconds before they are needed.
*   **Aggressive Wiping:** Every temporary buffer used for sensitive data is scrubbed using `SecureZeroMemory` immediately after use.

## 3. Stringless Core (No Plaintext Breadcrumbs)
Plaintext strings are the "breadcrumbs" of reverse engineering. Strings like `"Signature Mismatch"` or `"Invalid Token"` allow an attacker to find your security logic in seconds using static analysis.

*   **Opaque Error Codes:** The library emits no plaintext error strings in hardened mode. It operates exclusively on a strictly typed `enum class ErrorCode`, and `ErrorCodeToString(...)` collapses to a numeric/XORed representation by default.
*   **Magic-Numberless Core:** In an open-source library, unique hex constants become perfect signatures for static analysis. BurnerNet avoids public magic numbers entirely by compiling error codes down to small sequential integers that blend into ordinary control flow.
*   **Jump-Table Destruction:** Release builds harden `ErrorCode` stringification automatically, replacing recognizable switch-based strings with numeric output.
*   **Protocol Stealth:** Essential internal strings (like HTTP methods and headers) are stack-obfuscated and wiped after use to ensure a `strings` dump reveals nothing.
*   **Source-Drop Advantage (Recommended):** The preferred integration model is to compile BurnerNet's source directly inside the host project. That keeps setup simple and lets compile-time hardening be instantiated inside each downstream build instead of being frozen into one shared prebuilt library artifact.
*   **Import-Light Runtime:** On Windows, BurnerNet uses vendored `lazy_importer` for hidden API resolution in the hardened path instead of relying on large manual import-walking code.

## 4. Bring Your Own Weapons (Professional Hardening vs. Active Warfare)
Anti-Reverse Engineering (Anti-RE) is a cat-and-mouse game. BurnerNet is a **Professional Hardening** library, not an aggressive obfuscator. We target the sweet spot between **Security**, **Maintainability**, and **Performance**.

*   **No Spaghetti-Code Obfuscation:** We reject techniques like control-flow flattening or MBA that turn source code into an unmaintainable mess. BurnerNet's stealth is structural: clean C++20 design choices that still produce a dark binary.
*   **Weapon Mounts, Not Weapons:** Rather than forcing specific anti-debug, anti-VM, or anti-tamper logic that may break builds or create false positives, BurnerNet provides the welded mounts where those checks can run safely.
*   **Woven Logic:** Policy hooks are compiled into the transport path through concrete types, concepts, and hardened dispatch rather than standard virtual inheritance. That keeps the source auditable while making those checks harder to unplug at runtime.
*   **Respect for the Developer:** We provide the armor: hidden imports, mangled pointers, vtable-free dispatch, and secure transport defaults. You provide the weapons: debugger detection, VM heuristics, integrity scans, and application-specific enforcement.

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

### The Vision: The Hardening Sweet Spot
The goal of BurnerNet is to provide a **Fortified Transport Layer** that lives in the sweet spot of three competing requirements:

1. **Security:** Total binary stealth for static analysis and hardened resilience against dynamic hooking.
2. **Maintainability:** Clean, idiomatic C++20 source code that remains easy to audit, debug, and extend.
3. **Performance:** Low-overhead security primitives that avoid the traditional performance tax of aggressive obfuscation.

**We provide the armor; you provide the weapons.**

By staying in the category of **Professional Hardening**, BurnerNet remains a reliable high-performance tool for legitimate developers while still presenting a dark, expensive target for attackers. We move the ingredients through a secure pipe, keep the binary opaque where it matters, and avoid sacrificing the quality of the codebase to get there.
