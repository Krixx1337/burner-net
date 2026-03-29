#pragma once

#include "burner/net/config_bridge.h"
#include "burner/net/obfuscation_config.h"

#include <cstddef>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#endif

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
#pragma message("BurnerNet release build uses the default BURNER_OBF_LITERAL fallback; define a custom obfuscator via BURNERNET_CUSTOM_OBFUSCATOR_HEADER or your project config header.")
#endif
#endif

namespace burner::net {

inline void internal_default_wipe(char* ptr, size_t size) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    volatile char* volatile_ptr = ptr;
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = '\0';
    }
#endif
}

#ifndef BURNERNET_CUSTOM_WIPE
#define BURNERNET_CUSTOM_WIPE(ptr, size) ::burner::net::internal_default_wipe(ptr, size)
#endif

inline void SecureWipe(std::string& value) {
    if (value.empty()) {
        return;
    }

    BURNERNET_CUSTOM_WIPE(value.data(), value.size());
    value.clear();
}

} // namespace burner::net
