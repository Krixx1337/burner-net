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
*   **Streaming-First:** Response bodies can be processed in chunks rather than accumulated into large, static strings, minimizing the footprint of sensitive payloads.

## 3. Stringless Core (No Plaintext Breadcrumbs)
Plaintext strings are the "breadcrumbs" of reverse engineering. Strings like `"Signature Mismatch"` or `"Invalid Token"` allow an attacker to find your security logic in seconds using static analysis.

*   **Opaque Error Codes:** The library emits no plaintext error strings in hardened mode. It operates exclusively on a strictly typed `enum class ErrorCode`.
*   **Magic-Numberless Core:** In an open-source library, unique hex constants become perfect signatures for static analysis. BurnerNet avoids public magic numbers entirely by compiling error codes down to small sequential integers that blend into ordinary control flow.
*   **Jump-Table Destruction:** In hardened builds (`BURNERNET_HARDEN_ERRORS=1`), stringification switches are compiled out and replaced with generic integer output, preventing recognizable jump tables from being emitted into the binary.
*   **Protocol Stealth:** Essential internal strings (like HTTP methods and headers) are stack-obfuscated and wiped after use to ensure a `strings` dump reveals nothing.

## 4. Bring Your Own Weapons (Custom Integrity Hooks)
Anti-Reverse Engineering (Anti-RE) is a cat-and-mouse game. Rather than forcing a specific, heavy-handed anti-debug or anti-tamper implementation that might break your build, BurnerNet provides the **Weapon Mounts**.

*   **API Table Hooks:** Instead of standard IAT imports, developers can provide a custom function pointer table. This allows for stealthy manual mapping or syscall-based execution of cURL and Windows APIs.
*   **Verification Mounts:** We provide hooks inside the execution loop where developers can attach their own "Weapons"—such as anti-debug checks, heartbeat monitors, or memory integrity scans.
*   **Execution Witnesses:** Critical security paths (like HMAC verification) use state-machine witnesses to ensure logic hasn't been bypassed by "JMP" patches.

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

### The Goal
The goal of BurnerNet is to provide a **Fortified Transport Layer**. We provide the armor (Secure Networking and Memory Hygiene); you provide the weapons (Anti-RE and Business Logic). 

**By moving the "Ingredients" (Data) through a secure pipe and keeping the "Cook" (The Binary) opaque, we turn your application into a target that is too expensive to crack.**
