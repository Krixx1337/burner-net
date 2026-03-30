#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "export.h"
#include "error.h"
#include "policy.h"

namespace burner::net {

enum class LinkMode {
    Static,
    Dynamic
};

struct DependencyHashEntry {
    std::wstring dll_name;
    std::string sha256_hex;
};

struct DependencyIntegrityPolicy {
    bool enabled = false;
    bool fail_closed = true;
    std::vector<DependencyHashEntry> sha256_allowlist;
};

struct BootstrapConfig {
    LinkMode link_mode = LinkMode::Static;
    bool preload_dependencies = true;
    SecurityPolicy security_policy;
    std::filesystem::path dependency_directory;
    DependencyIntegrityPolicy integrity_policy;
    std::vector<std::wstring> dependency_dlls = {
#if defined(_WIN32) && defined(_DEBUG)
        L"libcurl-d.dll",
#elif defined(_WIN32)
        L"libcurl.dll",
#endif
    };
};

struct BootstrapResult {
    bool success = false;
    ErrorCode code = ErrorCode::None;
};

BURNER_API BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config);

} // namespace burner::net
