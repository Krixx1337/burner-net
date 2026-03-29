#pragma once

#include <cstdint>
#include <string>
#include <type_traits>

namespace hostile_core {

template <typename EnumType, std::uint32_t XorKey>
[[nodiscard]] inline std::string harden_error_code(EnumType code) {
    static_assert(std::is_enum_v<EnumType>);
    return std::to_string(static_cast<std::uint32_t>(code) ^ XorKey);
}

} // namespace hostile_core
