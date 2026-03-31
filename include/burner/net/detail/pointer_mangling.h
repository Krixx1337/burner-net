#pragma once

#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/detail/constexpr_obfuscation.h"

#include <atomic>
#include <cstdint>
#include <type_traits>
#include <utility>

#if defined(_MSC_VER)
#define BURNER_FORCEINLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define BURNER_FORCEINLINE __attribute__((always_inline)) inline
#else
#define BURNER_FORCEINLINE inline
#endif

namespace burner::net {
namespace detail {

inline std::atomic<std::uintptr_t> g_encoded_pointer_key{0};
inline std::atomic<std::uintptr_t> g_encoded_pointer_nonce{
    static_cast<std::uintptr_t>(obf::build_seed()) | static_cast<std::uintptr_t>(1)};

[[nodiscard]] inline std::uintptr_t mix_runtime_key(std::uintptr_t value) noexcept {
    value ^= value >> 30;
    value *= static_cast<std::uintptr_t>(0xBF58476D1CE4E5B9ull);
    value ^= value >> 27;
    value *= static_cast<std::uintptr_t>(0x94D049BB133111EBull);
    value ^= value >> 31;
    return value;
}

[[nodiscard]] inline std::uintptr_t derive_runtime_pointer_key(std::uintptr_t salt = 0) noexcept {
    std::uintptr_t stack_anchor = 0;
    const auto nonce = g_encoded_pointer_nonce.fetch_add(
        static_cast<std::uintptr_t>(0x9E3779B97F4A7C15ull),
        std::memory_order_relaxed);

    std::uintptr_t value = static_cast<std::uintptr_t>(obf::build_seed());
    value ^= reinterpret_cast<std::uintptr_t>(&g_encoded_pointer_key);
    value ^= reinterpret_cast<std::uintptr_t>(&stack_anchor);
    value ^= nonce;
    value ^= salt;
    value = mix_runtime_key(value);
    if (value == 0) {
        value = static_cast<std::uintptr_t>(0xA5A5A5A5A5A5A5A5ull);
    }
    return value;
}

inline void InitializeEncodedPointerKey(std::uintptr_t salt = 0) noexcept {
    std::uintptr_t expected = 0;
    const std::uintptr_t derived = derive_runtime_pointer_key(salt);
    (void)g_encoded_pointer_key.compare_exchange_strong(
        expected, derived, std::memory_order_release, std::memory_order_relaxed);
}

[[nodiscard]] inline std::uintptr_t current_encoded_pointer_key() noexcept {
    std::uintptr_t key = g_encoded_pointer_key.load(std::memory_order_acquire);
    if (key == 0) {
        InitializeEncodedPointerKey();
        key = g_encoded_pointer_key.load(std::memory_order_acquire);
    }
    return key;
}

[[nodiscard]] inline std::uintptr_t mba_xor(std::uintptr_t lhs, std::uintptr_t rhs) noexcept {
    const auto sum = add_deep<std::uintptr_t>(lhs, rhs);
    const auto carry_twice = static_cast<std::uintptr_t>((lhs & rhs) << 1);
    return sub_deep<std::uintptr_t>(sum, carry_twice);
}

} // namespace detail

template <typename T>
class EncodedPointer {
    static_assert(std::is_pointer_v<T>, "EncodedPointer requires a pointer type");

public:
    constexpr EncodedPointer() noexcept = default;
    constexpr EncodedPointer(std::nullptr_t) noexcept {}
    constexpr EncodedPointer(T pointer) noexcept {
        set(pointer);
    }

    constexpr EncodedPointer& operator=(std::nullptr_t) noexcept {
        m_encoded = 0;
        return *this;
    }

    constexpr EncodedPointer& operator=(T pointer) noexcept {
        set(pointer);
        return *this;
    }

    [[nodiscard]] BURNER_FORCEINLINE T get() const noexcept {
        if (m_encoded == 0) {
            return nullptr;
        }

        const auto decoded = detail::mba_xor(
            m_encoded, detail::current_encoded_pointer_key());
        return reinterpret_cast<T>(decoded);
    }

    template <typename... Args>
    BURNER_FORCEINLINE decltype(auto) operator()(Args&&... args) const {
        return get()(std::forward<Args>(args)...);
    }

    [[nodiscard]] explicit constexpr operator bool() const noexcept {
        return m_encoded != 0;
    }

private:
    constexpr void set(T pointer) noexcept {
        if (pointer == nullptr) {
            m_encoded = 0;
            return;
        }

        m_encoded = detail::mba_xor(
            reinterpret_cast<std::uintptr_t>(pointer),
            detail::current_encoded_pointer_key());
    }

    std::uintptr_t m_encoded = 0;
};

} // namespace burner::net

#undef BURNER_FORCEINLINE
