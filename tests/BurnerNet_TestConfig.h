#pragma once

#include <string>
#include <vector>

#define BURNERNET_ERROR_XOR 0x000000A5u
#define BURNERNET_SECURITY_SEED 0x13572468u

#ifndef BURNERNET_HARDEN_IMPORTS
#define BURNERNET_HARDEN_IMPORTS 0
#endif

#ifndef BURNER_OBF_LITERAL
#define BURNER_OBF_LITERAL(str) std::string(str)
#endif

#ifndef BURNERNET_ON_SIGNATURE_VERIFIED
#define BURNERNET_ON_SIGNATURE_VERIFIED(success, reason) \
    do {                                                 \
        (void)(success);                                 \
        (void)(reason);                                  \
    } while (0)
#endif

#ifndef BURNERNET_ON_TAMPER
#include <cstdlib>
#define BURNERNET_ON_TAMPER() std::abort()
#endif

#ifndef BURNERNET_GET_USER_AGENT
#define BURNERNET_GET_USER_AGENT() std::string("")
#endif

#ifndef BURNERNET_ON_ERROR
#define BURNERNET_ON_ERROR(code, url) \
    do {                              \
        (void)(code);                 \
        (void)(url);                  \
    } while (0)
#endif

namespace burnernet_test_config {

inline const std::vector<std::wstring> GetTrustedDependencies() {
    return {
        L"zlib1.dll",
        L"libcurl.dll"
    };
}

} // namespace burnernet_test_config
