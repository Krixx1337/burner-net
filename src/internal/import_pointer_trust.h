#pragma once

#include <string>
#include <vector>

namespace burner::net::internal {

bool IsFunctionPointerInAllowedModules(
    const void* fn,
    const std::vector<std::wstring>& allowed_module_basenames);

bool IsFunctionPointerExecutable(const void* fn);

bool IsFunctionPointerTrusted(
    const void* fn,
    const std::vector<std::wstring>& allowed_module_basenames);

} // namespace burner::net::internal
