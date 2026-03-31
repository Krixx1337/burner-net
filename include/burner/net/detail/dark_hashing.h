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

} // namespace burner::net::detail
