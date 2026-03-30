#pragma once

#include "burner/net/detail/constexpr_obfuscation.h"

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

        const auto decoded =
            m_encoded ^ static_cast<std::uintptr_t>(obf::build_seed());
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

        m_encoded =
            reinterpret_cast<std::uintptr_t>(pointer) ^
            static_cast<std::uintptr_t>(obf::build_seed());
    }

    std::uintptr_t m_encoded = 0;
};

} // namespace burner::net

#undef BURNER_FORCEINLINE
