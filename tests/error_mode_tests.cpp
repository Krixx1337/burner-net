#include "burner/net/error.h"

#include <cstdint>

int main() {
    using burner::net::ErrorCode;

    static_assert(static_cast<std::uint32_t>(ErrorCode::DisabledBackend) == 1);
    static_assert(static_cast<std::uint32_t>(ErrorCode::HardenedPersistentMtlsForbidden) == 43);

    if (burner::net::ErrorCodeToString(ErrorCode::DisabledBackend) != "E1") {
        return 1;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::HardenedPersistentMtlsForbidden) != "E43") {
        return 2;
    }
    return 0;
}
