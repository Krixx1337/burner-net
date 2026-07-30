#include "burner/net/error.h"

#include <cstdint>
#include <iostream>

int main() {
    using burner::net::ErrorCode;

    static_assert(static_cast<std::uint32_t>(ErrorCode::DisabledBackend) == 1);
    static_assert(static_cast<std::uint32_t>(ErrorCode::HardenedPersistentMtlsForbidden) == 43);
    static_assert(static_cast<std::uint32_t>(ErrorCode::OutOfMemory) == 51);
    static_assert(static_cast<std::uint32_t>(ErrorCode::MaximumGhostRuntimeRequired) == 64);

    if (burner::net::ErrorCodeToString(ErrorCode::DisabledBackend) != "E1") {
        std::cerr << "FAIL: diagnostic-off mapping for code 1 changed.\n";
        return 1;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::HardenedPersistentMtlsForbidden) != "E43") {
        std::cerr << "FAIL: diagnostic-off mapping for code 43 changed.\n";
        return 2;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::OutOfMemory) != "E51") {
        std::cerr << "FAIL: diagnostic-off mapping for code 51 changed.\n";
        return 3;
    }
    if (burner::net::ErrorCodeToString(ErrorCode::MaximumGhostRuntimeRequired) != "E64") {
        std::cerr << "FAIL: diagnostic-off mapping for code 64 changed.\n";
        return 4;
    }

    std::cout
        << "PASS: diagnostic-off ErrorCode mappings are compact and stable.\n"
        << "CTest also scans this executable for leaked symbolic error names.\n";
    return 0;
}
