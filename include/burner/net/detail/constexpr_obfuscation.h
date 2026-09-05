#pragma once

#include "burner/net/detail/build_config.h"
#include "burner/net/detail/dark_hash_utils.h"
#include "burner/net/detail/dark_simd.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace burner::net::obf {

[[nodiscard]] constexpr std::uint64_t hash_string(std::string_view value) noexcept {
    return ::burner::net::detail::fnv1a<std::uint64_t>(value);
}

[[nodiscard]] constexpr std::uint64_t hash_uint64(std::uint64_t value) noexcept {
    return ::burner::net::detail::split_mix64(value);
}

[[nodiscard]] consteval std::uint64_t hash_build_fragment(std::string_view fragment) noexcept {
    return hash_string(fragment);
}

[[nodiscard]] consteval std::uint64_t build_seed() noexcept {
    // Fixed build seed, identical in every translation unit. Earlier
    // revisions mixed __DATE__/__TIME__/__FILE__ here, so the same public
    // inline definitions (and the g_encoded_pointer_nonce initializer) had
    // different values per translation unit: an ODR violation that also
    // broke reproducible builds. Per-build uniqueness now comes only from
    // runtime entropy (pointer nonce, stack addresses); rotate this constant
    // deliberately if per-release obfuscation diversity is ever required.
    return 0x9E3779B97F4A7C15ull;
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

// Note: the obfuscation seed is derived from the literal itself
// (hash_string), never from __COUNTER__/__TIME__/__FILE__/__LINE__. A
// per-inclusion counter or timestamp would give the same literal different
// DarkLiteral instantiations in different translation units, violating the
// one-definition rule for every public inline definition that expands this
// macro (and breaking reproducible builds). MSVC Edit and Continue (/ZI)
// compatibility is preserved: no __LINE__ is used.
// BURNERNET_OBFUSCATE_STRINGS=0 expands to a plain string so the build
// option is honored instead of silently obfuscating anyway.
#if BURNERNET_OBFUSCATE_STRINGS
#define BURNER_OBF_LITERAL(str)                                                                \
    ::burner::net::detail::DarkLiteral<sizeof(str),                                            \
        ::burner::net::obf::hash_string(str)>{str}.resolve()
#else
#define BURNER_OBF_LITERAL(str) std::string(str)
#endif
