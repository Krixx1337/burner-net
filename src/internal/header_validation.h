#pragma once

#include <string_view>

namespace burner::net::internal {

bool IsValidHeaderName(std::string_view name);
bool IsValidHeaderValue(std::string_view value);
bool IsValidBearerToken(std::string_view token);
bool IsValidHttpsUrl(std::string_view url);

} // namespace burner::net::internal
