#pragma once

#include "burner/net/export.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace burner::hostile_core {

BURNER_API void secure_wipe(void* ptr, std::size_t size) noexcept;

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

} // namespace burner::hostile_core
