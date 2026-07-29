#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "detail/dark_callables.h"
#include "export.h"
#include "error.h"

namespace burner::net {

enum class LinkMode {
    Static,
    Dynamic
};

using IntegrityProvider = detail::CompactCallable<bool(const std::filesystem::path& dll_path, const std::wstring& dll_name)>;
using DependencyDirectoryGuard =
    detail::CompactCallable<bool(const std::filesystem::path& canonical_directory)>;

struct BootstrapConfig {
    LinkMode link_mode = LinkMode::Static;
    bool preload_dependencies = true;
    bool install_global_allocator_hooks = false;
    std::filesystem::path dependency_directory;
    DependencyDirectoryGuard dependency_directory_guard;
    IntegrityProvider integrity_provider;
    std::vector<std::wstring> dependency_dlls{};
};

struct BootstrapResult {
    bool success = false;
    ErrorCode code = ErrorCode::None;
};

BURNER_API BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config);
BURNER_API void ShutdownNetworkingRuntime() noexcept;
BURNER_API bool GlobalAllocatorHooksEnabled() noexcept;

} // namespace burner::net
