#pragma once

#include "burner/net/detail/constexpr_obfuscation.h"
#include "burner/net/detail/memory_hygiene.h"

#include <string>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace burner::net::obf {

template <typename TFn>
inline TFn resolve_import(std::string dll_name, std::string function_name) {
#if defined(_WIN32)
    HMODULE module = GetModuleHandleA(dll_name.c_str());
    if (module == nullptr) {
        module = LoadLibraryA(dll_name.c_str());
    }

    TFn resolved = nullptr;
    if (module != nullptr) {
        resolved = reinterpret_cast<TFn>(GetProcAddress(module, function_name.c_str()));
    }

    secure_wipe(dll_name);
    secure_wipe(function_name);
    return resolved;
#else
    secure_wipe(dll_name);
    secure_wipe(function_name);
    return nullptr;
#endif
}

} // namespace burner::net::obf

#define BURNER_HOSTILE_IMPORT(FnType, dll_lit, func_lit) \
    ::burner::net::obf::resolve_import<FnType>(BURNER_OBF_LITERAL(dll_lit), BURNER_OBF_LITERAL(func_lit))
