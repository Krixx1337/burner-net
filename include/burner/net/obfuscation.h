#pragma once

#ifndef HOSTILE_CORE_NAMESPACE
#define HOSTILE_CORE_NAMESPACE burner_hostile
#endif

#ifndef HOSTILE_CORE_EXPORT
#define HOSTILE_CORE_EXPORT BURNER_API
#endif

#include "burner/net/detail/constexpr_obfuscation.h"
#include "burner/net/detail/memory_hygiene.h"

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

#ifndef BURNERNET_HARDEN_IMPORTS
#define BURNERNET_HARDEN_IMPORTS 0
#endif

namespace burner::net {

inline void SecureWipe(std::string& value) {
    ::HOSTILE_CORE_NAMESPACE::secure_wipe(value.data(), value.size());
    value.clear();
}

template <typename T>
inline void SecureWipe(std::vector<T>& value) {
    ::HOSTILE_CORE_NAMESPACE::secure_wipe(value.data(), value.size() * sizeof(T));
    value.clear();
}

template <typename T>
inline void SecureWipe(std::span<T> value) {
    ::HOSTILE_CORE_NAMESPACE::secure_wipe(value.data(), value.size_bytes());
}

} // namespace burner::net
