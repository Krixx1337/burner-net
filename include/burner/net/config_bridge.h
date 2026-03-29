#pragma once

// 1. Include the user's config if they provided one.
// In Visual Studio, add BURNERNET_USER_CONFIG_HEADER="MyConfig.h" to Preprocessor Definitions.
#ifdef BURNERNET_USER_CONFIG_HEADER
#include BURNERNET_USER_CONFIG_HEADER
#endif

// 2. Provide safe defaults for every hook.
// If the developer did not define these in their config, BurnerNet falls back
// to standard, non-obfuscated behavior.

#ifndef BURNER_OBF_LITERAL
#include <string>
#define BURNER_OBF_LITERAL(str) std::string(str)
#endif

#ifndef BURNERNET_ERROR_XOR
#define BURNERNET_ERROR_XOR 0
#endif

#ifndef BURNERNET_ON_TAMPER
#include <cstdlib>
#define BURNERNET_ON_TAMPER() std::abort()
#endif

#ifndef BURNERNET_ON_SIGNATURE_VERIFIED
#define BURNERNET_ON_SIGNATURE_VERIFIED(success, reason) \
    do {                                                 \
        (void)(success);                                 \
        (void)(reason);                                  \
    } while (0)
#endif

#ifndef BURNERNET_GET_USER_AGENT
#define BURNERNET_GET_USER_AGENT() ""
#endif

#ifndef BURNERNET_ON_ERROR
#define BURNERNET_ON_ERROR(code, url) \
    do {                              \
        (void)(code);                 \
        (void)(url);                  \
    } while (0)
#endif
