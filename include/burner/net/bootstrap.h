#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "detail/dark_callables.h"
#include "export.h"
#include "error.h"
#include "policy.h"

namespace burner::net {

enum class LinkMode {
    Static,
    Dynamic
};

using IntegrityProvider = detail::CompactCallable<bool(const std::filesystem::path& dll_path, const std::wstring& dll_name)>;

struct DependencyIntegrityPolicy {
    bool enabled = false;
    bool fail_closed = true;
    IntegrityProvider integrity_provider;
};

struct BootstrapConfig {
    LinkMode link_mode = LinkMode::Static;
    bool preload_dependencies = true;
    SecurityPolicy security_policy;
    std::filesystem::path dependency_directory;
    DependencyIntegrityPolicy integrity_policy;
    std::vector<std::wstring> dependency_dlls{};
};

struct BootstrapResult {
    bool success = false;
    ErrorCode code = ErrorCode::None;
};

BURNER_API BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config);

} // namespace burner::net
