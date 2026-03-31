#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace burner::net::detail {

inline constexpr std::uint32_t fnv32_basis = 0x811C9DC5u;
inline constexpr std::uint32_t fnv32_prime = 0x01000193u;

inline constexpr std::uint64_t fnv64_basis = 0xCBF29CE484222325ull;
inline constexpr std::uint64_t fnv64_prime = 0x100000001B3ull;

inline constexpr std::uint64_t split_mix_increment = 0x9E3779B97F4A7C15ull;
inline constexpr std::uint64_t mix64_mul1 = 0xBF58476D1CE4E5B9ull;
inline constexpr std::uint64_t mix64_mul2 = 0x94D049BB133111EBull;

[[nodiscard]] constexpr char ascii_lower(char value) noexcept {
    return (value >= 'A' && value <= 'Z') ? static_cast<char>(value + ('a' - 'A')) : value;
}

template <typename T>
[[nodiscard]] constexpr T fnv1a(std::string_view value, bool case_insensitive = false) noexcept {
    static_assert(std::is_same_v<T, std::uint32_t> || std::is_same_v<T, std::uint64_t>,
                  "fnv1a only supports 32-bit or 64-bit unsigned integers");

    T hash = std::is_same_v<T, std::uint64_t> ? static_cast<T>(fnv64_basis) : static_cast<T>(fnv32_basis);
    const T prime = std::is_same_v<T, std::uint64_t> ? static_cast<T>(fnv64_prime) : static_cast<T>(fnv32_prime);

    for (char ch : value) {
        hash ^= static_cast<std::uint8_t>(case_insensitive ? ascii_lower(ch) : ch);
        hash *= prime;
    }

    return hash;
}

[[nodiscard]] constexpr std::uint32_t fnv1a_ascii_wide_ci(const wchar_t* value, std::size_t size) noexcept {
    std::uint32_t hash = fnv32_basis;
    for (std::size_t i = 0; i < size; ++i) {
        const wchar_t ch = value[i];
        const char ascii = (ch >= L'A' && ch <= L'Z') ? static_cast<char>(ch + (L'a' - L'A'))
                                                      : static_cast<char>(ch);
        hash ^= static_cast<std::uint8_t>(ascii);
        hash *= fnv32_prime;
    }
    return hash;
}

[[nodiscard]] constexpr std::uint64_t mix64(std::uint64_t value) noexcept {
    value = (value ^ (value >> 30)) * mix64_mul1;
    value = (value ^ (value >> 27)) * mix64_mul2;
    return value ^ (value >> 31);
}

[[nodiscard]] constexpr std::uint64_t split_mix64(std::uint64_t state) noexcept {
    return mix64(state + split_mix_increment);
}

} // namespace burner::net::detail
