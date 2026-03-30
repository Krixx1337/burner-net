#pragma once

#if defined(_WIN32)
#include "burner/net/external/lazy_importer/lazy_importer.hpp"
#endif

namespace burner::net::obf {}

#if defined(_WIN32)
#define BURNER_LAZY_MODULE(dll_lit) LI_MODULE(dll_lit).safe_cached()
#define BURNER_LAZY_IMPORT_IN(FnType, dll_lit, func_ident) \
    LI_FN(func_ident).in_safe<FnType>(BURNER_LAZY_MODULE(dll_lit))
#else
#define BURNER_LAZY_MODULE(dll_lit) nullptr
#define BURNER_LAZY_IMPORT_IN(FnType, dll_lit, func_ident) static_cast<FnType>(nullptr)
#endif
