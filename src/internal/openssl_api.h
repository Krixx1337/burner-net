#pragma once

// Internal header: not part of the BurnerNet public API.
// Defines the OpenSSL memory-hook function-pointer signatures used by
// openssl_sync.cpp to call CRYPTO_set_mem_functions without a static
// link dependency on OpenSSL.

#include <cstddef>

namespace burner::net::detail {

// Signatures that match OpenSSL's CRYPTO_malloc_fn / CRYPTO_realloc_fn /
// CRYPTO_free_fn typedefs.  OpenSSL passes the source file and line number
// as trailing parameters; our shims simply discard them.
using OpenSSL_malloc_fn  = void* (*)(std::size_t num,  const char* file, int line);
using OpenSSL_realloc_fn = void* (*)(void* addr, std::size_t num, const char* file, int line);
using OpenSSL_free_fn    = void  (*)(void* addr, const char* file, int line);

// Matches the signature of CRYPTO_set_mem_functions.
// Returns 1 on success, 0 if OpenSSL has already performed an allocation
// and locked its memory functions.
using CryptoSetMemFunctionsFn = int (*)(
    OpenSSL_malloc_fn  m,
    OpenSSL_realloc_fn r,
    OpenSSL_free_fn    f
);

using OpenSSLThreadStopFn = void (*)();

} // namespace burner::net::detail
