#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace hostile_core {

inline void secure_wipe(void* ptr, std::size_t size) noexcept {
    if (ptr == nullptr || size == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char* volatile_ptr = static_cast<volatile unsigned char*>(ptr);
    for (std::size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = 0;
    }
#endif
}

inline void secure_wipe(std::string& value) noexcept {
    secure_wipe(value.data(), value.capacity());
    value.clear();
}

template <typename T>
inline void secure_wipe(std::vector<T>& value) noexcept {
    secure_wipe(value.data(), value.capacity() * sizeof(T));
    value.clear();
}

template <typename T>
inline void secure_wipe(std::span<T> value) noexcept {
    secure_wipe(value.data(), value.size_bytes());
}

} // namespace hostile_core
