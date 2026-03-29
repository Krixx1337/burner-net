#pragma once

#include <string_view>

namespace burner::net::internal {

bool IsValidHeaderName(std::string_view name);
bool IsValidHeaderValue(std::string_view value);

} // namespace burner::net::internal
