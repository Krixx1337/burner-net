#pragma once

#include "burner/net/config_bridge.h"
#include "burner/net/detail/memory_hygiene.h"
#include "burner/net/obfuscation_config.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#ifndef BURNERNET_OBFUSCATE_STRINGS
#if defined(BURNER_OBFUSCATE_STRINGS)
#define BURNERNET_OBFUSCATE_STRINGS BURNER_OBFUSCATE_STRINGS
#else
#define BURNERNET_OBFUSCATE_STRINGS 1
#endif
#endif

#ifndef BURNERNET_HAS_CUSTOM_OBFUSCATOR
#define BURNERNET_HAS_CUSTOM_OBFUSCATOR 0
#endif

#if BURNERNET_OBFUSCATE_STRINGS && BURNERNET_HAS_CUSTOM_OBFUSCATOR
#include BURNERNET_CUSTOM_OBFUSCATOR_HEADER
#endif

#if defined(NDEBUG) && BURNERNET_OBFUSCATE_STRINGS && !BURNERNET_HAS_CUSTOM_OBFUSCATOR
#if defined(_MSC_VER) || defined(__clang__) || defined(__GNUC__)
#pragma message("BurnerNet release build uses the built-in HOSTILE_OBF fallback; define a custom obfuscator via BURNERNET_CUSTOM_OBFUSCATOR_HEADER or your project config header if you need a different scheme.")
#endif
#endif

namespace burner::net {

#ifndef BURNERNET_CUSTOM_WIPE
#define BURNERNET_CUSTOM_WIPE(ptr, size) ::hostile_core::secure_wipe(ptr, size)
#endif

inline void SecureWipe(std::string& value) {
    BURNERNET_CUSTOM_WIPE(value.data(), value.size());
    value.clear();
}

template <typename T>
inline void SecureWipe(std::vector<T>& value) {
    BURNERNET_CUSTOM_WIPE(value.data(), value.size() * sizeof(T));
    value.clear();
}

template <typename T>
inline void SecureWipe(std::span<T> value) {
    BURNERNET_CUSTOM_WIPE(value.data(), value.size_bytes());
}

} // namespace burner::net
