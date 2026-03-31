#pragma once

#include "burner/net/detail/memory_hygiene.h"

#include <cstddef>
#include <memory>
#include <type_traits>

namespace burner::net::detail {

template <typename T>
class WipingAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    WipingAllocator() noexcept = default;

    template <typename U>
    WipingAllocator(const WipingAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(size_type count) {
        return std::allocator<T>{}.allocate(count);
    }

    void deallocate(T* pointer, size_type count) noexcept {
        ::burner::net::obf::secure_wipe(pointer, count * sizeof(T));
        std::allocator<T>{}.deallocate(pointer, count);
    }

    template <typename U>
    struct rebind {
        using other = WipingAllocator<U>;
    };
};

template <typename T, typename U>
[[nodiscard]] constexpr bool operator==(WipingAllocator<T>, WipingAllocator<U>) noexcept {
    return true;
}

template <typename T, typename U>
[[nodiscard]] constexpr bool operator!=(WipingAllocator<T>, WipingAllocator<U>) noexcept {
    return false;
}

} // namespace burner::net::detail

