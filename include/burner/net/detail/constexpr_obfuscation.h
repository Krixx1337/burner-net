#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace hostile_core {

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

} // namespace hostile_core

#define HOSTILE_OBF(str)                                                                             \
    ::hostile_core::ObfuscatedString<sizeof(str), static_cast<std::uint8_t>((__LINE__ ^ __COUNTER__ \
                                                                              ^ __TIME__[7])        \
                                                                             & 0xFFu)>{str}
