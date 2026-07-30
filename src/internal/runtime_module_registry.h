#pragma once

#include "burner/net/error.h"

#include <memory>
#include <string>
#include <string_view>

namespace burner::net::detail {

struct RuntimeModule final {
    void* handle = nullptr;
    std::wstring basename;
};

using RuntimeModuleLease = std::shared_ptr<const RuntimeModule>;

RuntimeModuleLease AcquireRuntimeModule(std::string_view basename) noexcept;
ErrorCode MaximumGhostRuntimeError() noexcept;

} // namespace burner::net::detail
