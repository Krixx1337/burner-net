#pragma once

#include "burner/net/detail/dark_simd.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace burner::net::obf {

inline constexpr std::uint64_t split_mix_increment = 0x9e3779b97f4a7c15ull;
inline constexpr std::uint64_t fnv_offset_basis = 0xcbf29ce484222325ull;
inline constexpr std::uint64_t fnv_prime = 0x100000001b3ull;

[[nodiscard]] constexpr std::uint64_t mix64(std::uint64_t x) noexcept {
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    return x ^ (x >> 31);
}

[[nodiscard]] constexpr std::uint64_t split_mix64(std::uint64_t state) noexcept {
    return mix64(state + split_mix_increment);
}

[[nodiscard]] constexpr std::uint64_t hash_string(std::string_view value) noexcept {
    std::uint64_t hash = fnv_offset_basis;
    for (unsigned char ch : value) {
        hash ^= ch;
        hash *= fnv_prime;
    }
    return hash;
}

[[nodiscard]] constexpr std::uint64_t hash_uint64(std::uint64_t value) noexcept {
    return split_mix64(value);
}

[[nodiscard]] consteval std::uint64_t hash_build_fragment(std::string_view fragment) noexcept {
    return hash_string(fragment);
}

[[nodiscard]] consteval std::uint64_t build_seed() noexcept {
    std::uint64_t seed = hash_build_fragment(__DATE__);
    seed ^= split_mix64(hash_build_fragment(__TIME__));
    seed ^= split_mix64(hash_build_fragment(__FILE__));
    return mix64(seed);
}

[[nodiscard]] consteval std::uint32_t build_error_xor_key() noexcept {
    constexpr std::uint32_t max_value = (std::numeric_limits<std::uint32_t>::max)();
    const std::uint32_t folded = static_cast<std::uint32_t>(build_seed() & max_value);
    return folded == 0u ? 0xA5A5A5A5u : folded;
}

template <std::uint64_t Secret, std::uint8_t Mask>
struct ObfuscatedSecret {
    std::array<std::uint8_t, sizeof(std::uint64_t)> masked_bytes{};

    consteval ObfuscatedSecret() {
        for (std::size_t i = 0; i < masked_bytes.size(); ++i) {
            const auto byte = static_cast<std::uint8_t>((Secret >> (i * 8)) & 0xFFu);
            masked_bytes[i] = static_cast<std::uint8_t>(byte ^ Mask);
        }
    }

    [[nodiscard]] std::uint64_t resolve() const noexcept {
        volatile std::uint8_t mask = Mask;
        std::uint64_t secret = 0;

        for (std::size_t i = 0; i < masked_bytes.size(); ++i) {
            const volatile std::uint8_t masked = masked_bytes[i];
            secret |= static_cast<std::uint64_t>(masked ^ mask) << (i * 8);
        }

        return secret;
    }
};

template <std::uint64_t Secret, std::uint8_t Mask>
[[nodiscard]] consteval auto make_obfuscated_secret() {
    return ObfuscatedSecret<Secret, Mask>{};
}

template <std::size_t N, std::uint8_t Mask>
struct ObfuscatedString {
    std::array<char, N> masked_chars{};

    consteval explicit ObfuscatedString(const char (&value)[N]) {
        for (std::size_t i = 0; i + 1 < N; ++i) {
            masked_chars[i] = static_cast<char>(value[i] ^ Mask);
        }
        masked_chars[N - 1] = '\0';
    }

    [[nodiscard]] std::string resolve() const {
        std::string result(N - 1, '\0');
        volatile std::uint8_t mask = Mask;

        for (std::size_t i = 0; i + 1 < N; ++i) {
            const volatile char masked = masked_chars[i];
            result[i] = static_cast<char>(masked ^ mask);
        }

        return result;
    }
};

} // namespace burner::net::obf

// Note: __LINE__ is intentionally omitted so MSVC Edit and Continue (/ZI)
// keeps this as a valid compile-time expression in default Debug builds.
#define BURNER_OBF_LITERAL(str)                                                                \
    ::burner::net::detail::DarkLiteral<sizeof(str),                                            \
        ((static_cast<std::uint64_t>(__COUNTER__) << 32u) ^                                    \
            static_cast<std::uint64_t>(__TIME__[6]) ^                                          \
            (static_cast<std::uint64_t>(__TIME__[7]) << 8u))>{str}.resolve()
