# BurnerNet Security Audit Goals

This document describes the security and forensic-hygiene goals BurnerNet is designed to support.

It is not a point-in-time audit report and it is not a guarantee that every downstream build, dependency set, or runtime environment will exhibit every property listed here. Instead, it provides a stable checklist for evaluating whether a particular BurnerNet integration is preserving the library's intended hardening posture.

Use this document for:
- security reviews
- release-readiness checks
- regression analysis after transport or bootstrap changes
- downstream integration validation

For a point-in-time audited build example, see [BINARY_STEALTH_AUDIT.md](BINARY_STEALTH_AUDIT.md).

## 1. Static Footprint Goals

These checks answer: "What does the binary reveal before it runs?"

Target outcomes:
- obvious transport literals should be minimized in library-controlled code paths
- hardened builds should avoid leaking descriptive internal error strings
- transport hardening paths should avoid unnecessary imports and metadata exposure
- application-owned trust anchors should remain in application code rather than in shared BurnerNet defaults

Questions to ask:
- Do string dumps reveal internal URLs, default canary endpoints, or reusable trust anchors?
- Does the import table expose networking or cryptographic dependencies that should be resolved through the selected integration mode?
- Are there static symbols or metadata that make trust-decision code paths easy to classify?
- Do low-level allocator assumptions still match platform alignment requirements so the hardening layer remains stable under real transport/TLS workloads?

## 2. Dynamic Tracing Goals

These checks answer: "How much can an observer learn by stepping through the live request path?"

Target outcomes:
- stack isolation should make the transport path less directly traceable from consumer logic
- sensitive policy hooks should avoid predictable virtual-dispatch surfaces where practical
- transport execution should not create one long-lived, easy-to-hook global object when the use case calls for short-lived clients

Questions to ask:
- Does the call stack directly expose the business-logic caller in hardened request flows?
- Are sensitive hooks or trust decisions centralized behind easy-to-patch runtime dispatch points?
- Does the application keep high-trust networking state alive longer than necessary?

## 3. Memory Hygiene Goals

These checks answer: "What sensitive material remains in process memory after the request path completes?"

Target outcomes:
- BurnerNet-managed transport buffers should be wiped as they leave managed lifetime
- temporary request/response fragments should have short memory residency
- worker-thread stack cleanup should reduce leftover transport fragments after request completion
- provider-fetched secrets should be materialized close to use and not retained in long-lived config state
- backend-specific side effects such as per-thread error state or transport-side caches should be reviewed alongside the primary request buffers

Questions to ask:
- Are request URLs, auth headers, or response bodies lingering in process memory longer than expected?
- Are allocator hooks still active for the transport/TLS backend path in the selected build mode?
- Are isolated worker threads cleaning up backend-specific per-thread state where supported?
- Are backend-specific side effects such as TLS session caches, DNS retention, or thread-local error queues being reviewed and purged where the selected backend allows it?
- Are application secrets being passed through provider callbacks or parked in long-lived globals?

Important scope note:
- BurnerNet can only wipe memory inside its own authority. OS-level caches, loader metadata, kernel telemetry, and third-party runtime artifacts may still exist outside that scope.

## 4. Network Trust Goals

These checks answer: "How much does the client trust the host and local network by default?"

Target outcomes:
- high-trust request paths should not depend blindly on system DNS, system proxy, or ambient trust stores
- certificate validation, pinning, response verification, and transport checks should remain explicit and application-owned
- DNS-over-HTTPS, pinning, and response verification should be opt-in where they affect trust semantics

Questions to ask:
- Are sensitive requests still exposed to local proxy interception or DNS hijacking?
- Does the application distinguish between transport success and trust success?
- Are response signatures, pins, bootstrap integrity checks, and similar trust anchors owned by the application?

## 5. Integration Hygiene Goals

These checks answer: "Did the downstream integration preserve the hardening properties that BurnerNet expects?"

Target outcomes:
- the selected integration mode should match the deployment goal
- bootstrap mode should explicitly list packaged runtime DLLs and verify them in application code when required
- bootstrap mode should preserve a trustworthy verification-to-load path rather than leaving a file-swap window between integrity checks and module mapping
- architecture, linkage mode, runtime DLL set, and build configuration should remain aligned
- examples and consumer templates should stay runnable by default unless they are clearly placeholder-gated

Questions to ask:
- Did the consumer accidentally enable bootstrap/hardened-import mode without calling `InitializeNetworkingRuntime(...)`?
- Are runtime DLL names, architecture, and dependency layout consistent with the active configuration?
- Are docs and examples still aligned with the current API and intended default path?

## 6. Regression Review Questions

When reviewing a change, ask:
- Did this change introduce new plaintext identifiers or reusable trust anchors?
- Did this change lengthen the lifetime of sensitive buffers or clients?
- Did this change make bootstrap or runtime loading less explicit?
- Did this change weaken transport verification, response verification, or trust-boundary clarity?
- Did this change make the examples or integration guides more misleading than the code?

## 7. Interpreting Results

A failed goal does not always mean "the library is broken." It means one of these is true:
- the current build/integration mode does not match the threat model
- a hardening regression was introduced
- an application-owned trust decision was left implicit
- an audit claim should be narrowed or re-scoped

BurnerNet is best understood as a hardening layer with explicit scope:
- it can reduce transport visibility and memory residue
- it can make trust decisions more explicit and application-owned
- it cannot erase all OS/runtime artifacts or replace application-specific secrets and verification logic

## 8. Recommended Companion Docs

- Architectural intent: [../PRINCIPLES.md](../PRINCIPLES.md)
- Practical usage: [USAGE_BEST_PRACTICES.md](USAGE_BEST_PRACTICES.md)
- CMake integration: [CMAKE_INTEGRATION.md](CMAKE_INTEGRATION.md)
- Visual Studio integration: [VISUAL_STUDIO_INTEGRATION.md](VISUAL_STUDIO_INTEGRATION.md)
- Audit snapshot: [BINARY_STEALTH_AUDIT.md](BINARY_STEALTH_AUDIT.md)
