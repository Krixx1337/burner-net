#pragma once

#ifndef HOSTILE_CORE_EXPORT
#define HOSTILE_CORE_EXPORT BURNER_API
#endif

#include "burner/net/detail/build_config.h"
#include "burner/net/detail/constexpr_obfuscation.h"
#include "burner/net/detail/memory_hygiene.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace burner::net {

inline void SecureWipe(std::string& value) {
    ::burner::net::obf::secure_wipe(value);
}

template <typename Traits, typename Alloc>
inline void SecureWipe(std::basic_string<char, Traits, Alloc>& value) {
    ::burner::net::obf::secure_wipe(value);
}

inline void SecureWipe(SecureString& value) {
    value.clear();
}

template <typename T>
inline void SecureWipe(std::vector<T>& value) {
    ::burner::net::obf::secure_wipe(value);
}

template <typename T, typename Alloc>
inline void SecureWipe(std::vector<T, Alloc>& value) {
    ::burner::net::obf::secure_wipe(value);
}

inline void SecureWipe(SecureBuffer& value) {
    value.clear();
}

template <typename T>
inline void SecureWipe(std::span<T> value) {
    ::burner::net::obf::secure_wipe(value.data(), value.size_bytes());
}

} // namespace burner::net
