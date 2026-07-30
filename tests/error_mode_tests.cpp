#include "burner/net/error.h"

#include <cstdint>

int main() {
    using burner::net::ErrorCode;

    static_assert(static_cast<std::uint32_t>(ErrorCode::DisabledBackend) == 1);
    static_assert(static_cast<std::uint32_t>(ErrorCode::HardenedPersistentMtlsForbidden) == 43);
    static_assert(static_cast<std::uint32_t>(ErrorCode::OutOfMemory) == 51);
    static_assert(static_cast<std::uint32_t>(ErrorCode::MaximumGhostRuntimeRequired) == 64);

    if (burner::net::ErrorCodeToString(ErrorCode::DisabledBackend) != "E1") {
        return 1;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::HardenedPersistentMtlsForbidden) != "E43") {
        return 2;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::OutOfMemory) != "E51") {
        return 3;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::MaximumGhostRuntimeRequired) != "E64") {
        return 4;
    }
    return 0;
}
