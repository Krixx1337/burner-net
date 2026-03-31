#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace burner::net::detail {

inline constexpr std::uint32_t dark_fnv_offset_basis = 0x811C9DC5u;
inline constexpr std::uint32_t dark_fnv_prime = 0x01000193u;

[[nodiscard]] consteval std::uint32_t fnv1a(const char* value, std::size_t size) noexcept {
    std::uint32_t hash = dark_fnv_offset_basis;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= static_cast<std::uint8_t>(value[i]);
        hash *= dark_fnv_prime;
    }
    return hash;
}

template <std::size_t N>
[[nodiscard]] consteval std::uint32_t fnv1a(const char (&value)[N]) noexcept {
    static_assert(N > 0);
    return fnv1a(value, N - 1);
}

[[nodiscard]] constexpr char ascii_lower(char value) noexcept {
    return (value >= 'A' && value <= 'Z') ? static_cast<char>(value + ('a' - 'A')) : value;
}

[[nodiscard]] consteval std::uint32_t fnv1a_ci(const char* value, std::size_t size) noexcept {
    std::uint32_t hash = dark_fnv_offset_basis;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= static_cast<std::uint8_t>(ascii_lower(value[i]));
        hash *= dark_fnv_prime;
    }
    return hash;
}

template <std::size_t N>
[[nodiscard]] consteval std::uint32_t fnv1a_ci(const char (&value)[N]) noexcept {
    static_assert(N > 0);
    return fnv1a_ci(value, N - 1);
}

[[nodiscard]] constexpr std::uint32_t fnv1a_runtime(std::string_view value) noexcept {
    std::uint32_t hash = dark_fnv_offset_basis;
    for (unsigned char byte : value) {
        hash ^= byte;
        hash *= dark_fnv_prime;
    }
    return hash;
}

[[nodiscard]] constexpr std::uint32_t fnv1a_runtime_ci(std::string_view value) noexcept {
    std::uint32_t hash = dark_fnv_offset_basis;
    for (char ch : value) {
        hash ^= static_cast<std::uint8_t>(ascii_lower(ch));
        hash *= dark_fnv_prime;
    }
    return hash;
}

} // namespace burner::net::detail
