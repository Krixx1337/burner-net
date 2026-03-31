#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace burner::net::obf {
void secure_wipe(void* ptr, std::size_t size) noexcept;
}

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

namespace burner::net {

using DarkString = std::basic_string<char, std::char_traits<char>, detail::WipingAllocator<char>>;

template <typename T>
using DarkVector = std::vector<T, detail::WipingAllocator<T>>;

} // namespace burner::net
