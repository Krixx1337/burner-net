#pragma once

#include "burner/net/detail/dark_hash_utils.h"

namespace burner::net::detail {

inline constexpr std::uint32_t dark_fnv_offset_basis = fnv32_basis;
inline constexpr std::uint32_t dark_fnv_prime = fnv32_prime;

[[nodiscard]] consteval std::uint32_t fnv1a(const char* value, std::size_t size) noexcept {
    return ::burner::net::detail::fnv1a<std::uint32_t>(std::string_view{value, size});
}

template <std::size_t N>
[[nodiscard]] consteval std::uint32_t fnv1a(const char (&value)[N]) noexcept {
    static_assert(N > 0);
    return fnv1a(value, N - 1);
}

[[nodiscard]] consteval std::uint32_t fnv1a_ci(const char* value, std::size_t size) noexcept {
    return ::burner::net::detail::fnv1a<std::uint32_t>(std::string_view{value, size}, true);
}

template <std::size_t N>
[[nodiscard]] consteval std::uint32_t fnv1a_ci(const char (&value)[N]) noexcept {
    static_assert(N > 0);
    return fnv1a_ci(value, N - 1);
}

[[nodiscard]] constexpr std::uint32_t fnv1a_runtime(std::string_view value) noexcept {
    return ::burner::net::detail::fnv1a<std::uint32_t>(value);
}

[[nodiscard]] constexpr std::uint32_t fnv1a_runtime_ci(std::string_view value) noexcept {
    return ::burner::net::detail::fnv1a<std::uint32_t>(value, true);
}

// ---------------------------------------------------------------------------
// OpenSSL libcrypto module hashes
// OpenSSL 3.x and 1.1.x each ship separate DLL names on Windows, and x64
// builds add a "-x64" suffix.  We pre-compute all four variants so the syncer
// can iterate them without embedding plain-text strings.
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kLibCrypto3x64DllHash   = fnv1a_ci("libcrypto-3-x64.dll");
inline constexpr std::uint32_t kLibCrypto3DllHash      = fnv1a_ci("libcrypto-3.dll");
inline constexpr std::uint32_t kLibCrypto1_1x64DllHash = fnv1a_ci("libcrypto-1_1-x64.dll");
inline constexpr std::uint32_t kLibCrypto1_1DllHash    = fnv1a_ci("libcrypto-1_1.dll");

// Hash of the function used to inject our wiping allocators into OpenSSL.
inline constexpr std::uint32_t kCryptoSetMemFunctionsHash = fnv1a("CRYPTO_set_mem_functions");

// ---------------------------------------------------------------------------
// libcurl function hash
// ---------------------------------------------------------------------------

// Hash of the function used to inject our wiping allocators into libcurl.
inline constexpr std::uint32_t kCurlGlobalInitMemHash = fnv1a("curl_global_init_mem");

} // namespace burner::net::detail
