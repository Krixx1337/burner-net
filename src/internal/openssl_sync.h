#pragma once

// Internal header: not part of the BurnerNet public API.

namespace burner::net {

class SecurityPolicy;

// Attempts to inject BurnerNet's wiping allocators into OpenSSL by resolving
// CRYPTO_set_mem_functions dynamically from any libcrypto variant that is
// already loaded in the process.
//
// Call this as early as possible - before any OpenSSL allocation occurs.
// If OpenSSL has already locked its memory functions (i.e. an allocation
// already happened), policy.OnTamper() is invoked because memory hygiene for
// TLS key material can no longer be guaranteed for this session.
//
// Subsequent calls are silently ignored once the hooks have been applied.
void TryApplyOpenSSLHooks(const SecurityPolicy& policy) noexcept;

// Best-effort worker-thread cleanup for OpenSSL per-thread state.
// Safe to call even when OpenSSL is not present or exports are unavailable.
void TryInvokeOpenSSLThreadStop() noexcept;

} // namespace burner::net
