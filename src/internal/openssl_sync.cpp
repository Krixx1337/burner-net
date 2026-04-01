#include "openssl_sync.h"
#include "openssl_api.h"

#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/wiping_alloc_engine.h"
#include "burner/net/policy.h"

#include <atomic>

#ifdef _WIN32
#include "burner/net/detail/kernel_resolver.h"
#endif

namespace burner::net {

namespace {

#ifdef _WIN32

// ---------------------------------------------------------------------------
// Thin shims: discard OpenSSL's file/line metadata, forward to Phase 1 hooks.
// ---------------------------------------------------------------------------

static void* openssl_malloc_shim(std::size_t size, const char* /*file*/, int /*line*/) noexcept {
    return detail::alloc::dark_malloc(size);
}

static void* openssl_realloc_shim(void* ptr, std::size_t new_size, const char* /*file*/, int /*line*/) noexcept {
    return detail::alloc::dark_realloc(ptr, new_size);
}

static void openssl_free_shim(void* ptr, const char* /*file*/, int /*line*/) noexcept {
    detail::alloc::dark_free(ptr);
}

// Hashes of every libcrypto DLL name variant we might encounter.
constexpr std::uint32_t kCryptoModuleHashes[] = {
    detail::kLibCrypto3x64DllHash,
    detail::kLibCrypto3DllHash,
    detail::kLibCrypto1_1x64DllHash,
    detail::kLibCrypto1_1DllHash,
};

#endif // _WIN32

// Set to true once our shims have been successfully registered with OpenSSL.
// Prevents false tamper alerts on subsequent calls after a successful hook.
static std::atomic<bool> s_hooks_applied{false};

} // namespace

void TryApplyOpenSSLHooks(const SecurityPolicy& policy) noexcept {
    // Fast-path: hooks are already in place; nothing more to do.
    if (s_hooks_applied.load(std::memory_order_acquire)) {
        return;
    }

#ifdef _WIN32
    for (const std::uint32_t module_hash : kCryptoModuleHashes) {
        void* const module_base = detail::KernelResolver::GetSystemModule(module_hash);
        if (module_base == nullptr) {
            continue; // This variant of libcrypto is not loaded; try the next.
        }

        void* const fn_ptr = detail::KernelResolver::ResolveInternalExport(
            module_base, detail::kCryptoSetMemFunctionsHash);
        if (fn_ptr == nullptr) {
            continue; // Unexpected: found the DLL but not the export; try next.
        }

        auto* set_mem_fn = reinterpret_cast<detail::CryptoSetMemFunctionsFn>(fn_ptr);
        const int result = set_mem_fn(
            &openssl_malloc_shim,
            &openssl_realloc_shim,
            &openssl_free_shim);

        if (result != 0) {
            // Success: OpenSSL accepted our hooks.
            s_hooks_applied.store(true, std::memory_order_release);
        } else {
            // OpenSSL had already performed an allocation before we could
            // hook it.  TLS key material written to the default heap before
            // this point will not be wiped.  Trigger the tamper policy.
            policy.OnTamper();
        }

        // Whether we succeeded or triggered a tamper, we found libcrypto and
        // made an attempt.  No need to iterate further variants.
        return;
    }
    // libcrypto is not loaded yet; a future call (after bootstrap loads it)
    // will complete the hook.
#else
    (void)policy;
#endif // _WIN32
}

} // namespace burner::net
