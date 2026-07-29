#pragma once

// Internal header: not part of the BurnerNet public API.

namespace burner::net {

// Attempts to inject BurnerNet's wiping allocators into OpenSSL by resolving
// CRYPTO_set_mem_functions dynamically from any libcrypto variant that is
// already loaded in the process.
//
// Call this as early as possible - before any OpenSSL allocation occurs.
// Returns false when hooks cannot be installed.
[[nodiscard]] bool TryApplyOpenSSLHooks() noexcept;

// Best-effort worker-thread cleanup for OpenSSL per-thread state.
// Safe to call even when OpenSSL is not present or exports are unavailable.
void TryInvokeOpenSSLThreadStop() noexcept;

} // namespace burner::net
