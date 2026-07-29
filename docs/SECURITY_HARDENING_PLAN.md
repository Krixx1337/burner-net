# BurnerNet Release-Hardening Plan

## Summary

Fix all High findings plus related validation, wiping, auditor, and rollback defects. Preserve public method signatures where practical, but prioritize fail-closed behavior over old runtime behavior.

## Key Changes

- Harden response trust flow:
  - Reject `OnChunkReceived` combined with response verification before network activity.
  - Run verifier before `OnResponseReceived`.
  - Wipe body, headers, and telemetry on verification failure.
- Make credentials fail closed:
  - Abort when mTLS or bearer providers fail or return invalid material.
  - Fully reset easy-handle state after each request so copied keys and passwords are released immediately.
- Harden curl and memory handling:
  - Add checked allocator arithmetic.
  - Check every security-relevant `curl_easy_setopt`.
  - Preserve and clean `curl_slist` ownership on append failure.
  - Validate header controls, bearer tokens, timeouts, and HTTPS DoH URLs.
  - Make wipe helpers safe for non-trivial vectors and wipe discarded string capacity.
- Fix bootstrap lifecycle:
  - Validate DLL entries as basenames inside a canonical, non-reparse dependency directory.
  - Hold file and directory locks through verification and loading; compare file identity.
  - Publish modules only after complete success and roll back partial initialization.
  - Give sessions shared ownership of the exact verified `HMODULE`; shutdown defers unloading until the final session ends.
- Make empty security audits return `Inconclusive`, never `Trusted`.

## Public API and Documentation

- Append stable `ErrorCode` values for curl-option failure, credential failure, invalid credentials, unsupported verified streaming, invalid Hardened DoH, invalid bootstrap dependency, unavailable runtime, and out-of-memory failure.
- Keep `ShutdownNetworkingRuntime()` signature unchanged.
- Document new callback ordering, fail-closed provider contract, verified-streaming restriction, and runtime shutdown lifetime.

## Test Plan

- Add focused regression tests for allocator overflow, provider failure, verification ordering, response wiping, invalid headers and DoH, slist and setopt failures, and empty audits.
- Add Windows bootstrap tests for partial rollback, path rejection, exact-module ownership, and shutdown with live clients.
- Run targeted BurnerNet unit, error-mode, binary-string, Hardened-import, x64, and x86 builds; run live integration tests where network access permits.
- Run AddressSanitizer coverage for allocator and wipe-helper cases.

## Assumptions

- Security-first behavior changes are accepted.
- Verified streaming is rejected before transport rather than redesigned around authenticated framing.
- Error values remain append-only.
- Work stays inside `libs/burner-net`; no root architecture or unrelated cleanup changes.

## Implementation Status

Completed on 2026-07-29.

- Response verification now precedes trusted response callbacks; failed verification wipes response data.
- Verified streaming and invalid provider output fail before network I/O.
- Curl options, slist ownership, allocator arithmetic, credentials, headers, bearer tokens, timeouts, and Hardened DoH are checked fail-closed.
- Full easy-handle reset releases copied mTLS material after every request.
- Bootstrap validates canonical non-reparse paths, rolls back unpublished modules, and gives sessions shared ownership of the exact verified module.
- Empty security audits return `Inconclusive`.
- `PRINCIPLES.md` and usage docs reflect the hardened contracts.

Validation completed:

- x64 Debug standard: unit, error-mode, binary-string, bootstrap lifecycle, and live integration tests passed.
- x64 Debug Hardened imports: unit, error-mode, binary-string, and bootstrap lifecycle tests passed.
- x86 Debug Hardened imports: unit, error-mode, binary-string, and bootstrap lifecycle tests passed.
- x64 AddressSanitizer: allocator-overflow and non-trivial wipe tests passed with container checks enabled; legacy post-`clear()` raw-buffer wipe assertions passed with container-overflow annotations disabled because those assertions intentionally inspect storage outside the container's live range.
