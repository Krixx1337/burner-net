#pragma once

#include <atomic>
#include <concepts>
#include <cstdint>
#include <type_traits>

namespace burner::net::detail {

template <typename T>
concept DarkIntegral = std::integral<T> &&
    (!std::same_as<std::remove_cv_t<T>, bool>) &&
    (sizeof(std::remove_cv_t<T>) <= sizeof(std::uint64_t));

inline void dark_compiler_barrier() noexcept {
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

template <DarkIntegral T>
[[nodiscard]] inline T add_deep(T x, T y) noexcept {
    dark_compiler_barrier();
    volatile T vx = x;
    volatile T vy = y;
    dark_compiler_barrier();

    volatile T t0 = static_cast<T>(~(static_cast<T>(~vx) & static_cast<T>(~vy)));
    volatile T t1 = static_cast<T>(~(static_cast<T>(~vx) | static_cast<T>(~vy)));
    dark_compiler_barrier();

    const T a = t0;
    const T b = t1;
    volatile T half = static_cast<T>(a ^ b);
    volatile T carry = static_cast<T>((a & b) << 1);
    dark_compiler_barrier();

    const T h = half;
    const T c = carry;
    volatile T result = static_cast<T>((h ^ c) + static_cast<T>((h & c) << 1));
    dark_compiler_barrier();
    return result;
}

template <DarkIntegral T>
[[nodiscard]] inline T add_deep_alt(T x, T y) noexcept {
    dark_compiler_barrier();
    volatile T vx = x;
    volatile T vy = y;
    dark_compiler_barrier();

    const T a = static_cast<T>(static_cast<T>(~vx) & static_cast<T>(vy));
    const T b = static_cast<T>(static_cast<T>(vx) & static_cast<T>(~vy));
    volatile T c = static_cast<T>(a | b);
    volatile T d = static_cast<T>(~(static_cast<T>(~vx) | static_cast<T>(~vy)));
    dark_compiler_barrier();

    const T cv = c;
    const T dv = d;
    volatile T doubled = static_cast<T>(dv + dv);
    dark_compiler_barrier();

    const T ev = doubled;
    volatile T result = static_cast<T>((cv ^ ev) + static_cast<T>((cv & ev) << 1));
    dark_compiler_barrier();
    return result;
}

template <DarkIntegral T>
[[nodiscard]] inline T sub_deep(T x, T y) noexcept {
    dark_compiler_barrier();
    volatile T vy = y;
    dark_compiler_barrier();

    const T neg_y = static_cast<T>(~vy);
    constexpr T one = static_cast<T>(1);
    volatile T t0 = static_cast<T>(~(static_cast<T>(~neg_y) & static_cast<T>(~one)));
    volatile T t1 = static_cast<T>(~(static_cast<T>(~neg_y) | static_cast<T>(~one)));
    dark_compiler_barrier();

    const T a0 = t0;
    const T a1 = t1;
    volatile T neg_result = static_cast<T>((a0 ^ a1) + static_cast<T>((a0 & a1) << 1));
    dark_compiler_barrier();

    volatile T vx = x;
    dark_compiler_barrier();

    const T xv = vx;
    const T nr = neg_result;
    const T da = static_cast<T>(static_cast<T>(~xv) & nr);
    const T db = static_cast<T>(xv & static_cast<T>(~nr));
    volatile T dc = static_cast<T>(da | db);
    volatile T dd = static_cast<T>(~(static_cast<T>(~xv) | static_cast<T>(~nr)));
    dark_compiler_barrier();

    const T cv = dc;
    volatile T result = static_cast<T>(cv + static_cast<T>(static_cast<T>(dd) << 1));
    dark_compiler_barrier();
    return result;
}

template <DarkIntegral T>
[[nodiscard]] inline T mba_xor(T lhs, T rhs) noexcept {
    const auto sum = add_deep<T>(lhs, rhs);
    const auto carry_twice = static_cast<T>((lhs & rhs) << 1);
    return sub_deep<T>(sum, carry_twice);
}

[[nodiscard]] consteval std::uint64_t dark_mix64(std::uint64_t value) noexcept {
    value ^= value >> 30;
    value *= 0xBF58476D1CE4E5B9ull;
    value ^= value >> 27;
    value *= 0x94D049BB133111EBull;
    value ^= value >> 31;
    return value;
}

template <typename T, T Value, std::uint64_t Salt>
[[nodiscard]] inline T mask_integer_constant() noexcept {
    using unsigned_type = std::make_unsigned_t<T>;
    constexpr auto bit_count = static_cast<unsigned_type>(sizeof(T) * 8u);
    constexpr unsigned_type salt_bits = static_cast<unsigned_type>(dark_mix64(Salt));
    constexpr unsigned_type rotate = static_cast<unsigned_type>((salt_bits % (bit_count - 1u)) + 1u);
    constexpr unsigned_type left = static_cast<unsigned_type>(salt_bits << rotate);
    constexpr unsigned_type right = static_cast<unsigned_type>(salt_bits >> (bit_count - rotate));
    constexpr unsigned_type bias_bits = static_cast<unsigned_type>((left | right) ^ salt_bits);
    constexpr T bias = static_cast<T>(bias_bits);
    return add_deep<T>(sub_deep<T>(Value, bias), bias);
}

} // namespace burner::net::detail

#define BURNER_MASK_INT(value)                                                                      \
    ([]() {                                                                                         \
        using burner_mask_type = std::decay_t<decltype(value)>;                                     \
        static_assert(::burner::net::detail::DarkIntegral<burner_mask_type>);                       \
        return ::burner::net::detail::mask_integer_constant<burner_mask_type,                       \
            static_cast<burner_mask_type>(value),                                                   \
            ((static_cast<std::uint64_t>(__COUNTER__) << 32u) ^                                     \
                static_cast<std::uint64_t>(__TIME__[0]) ^                                           \
                (static_cast<std::uint64_t>(__TIME__[7]) << 8u))>();                                \
    }())
