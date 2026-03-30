#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

namespace HOSTILE_CORE_NAMESPACE {

template <typename EnumType>
[[nodiscard]] inline std::string harden_error_code(EnumType code, std::uint32_t xor_key) {
    static_assert(std::is_enum_v<EnumType>);
    return std::to_string(static_cast<std::uint32_t>(code) ^ xor_key);
}

} // namespace HOSTILE_CORE_NAMESPACE
