#pragma once

#include "curl_api.h"
#include "burner/net/http.h"
#include "internal/runtime_module_registry.h"

#include <memory>

namespace burner::net {

class CurlSession {
public:
    explicit CurlSession(CurlApi api, detail::RuntimeModuleLease module_lease = {});
    ~CurlSession();

    CurlSession(const CurlSession&) = delete;
    CurlSession& operator=(const CurlSession&) = delete;
    CurlSession(CurlSession&&) = delete;
    CurlSession& operator=(CurlSession&&) = delete;

    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] CURL* EasyHandle() const noexcept;
    [[nodiscard]] const CurlApi& Api() const noexcept;

    void Reset() const;

private:
    friend struct CurlHttpClientTestAccess;

    CurlApi m_api;
    detail::RuntimeModuleLease m_module_lease;
    CURL* m_easy = nullptr;
};

enum class GlobalAllocatorHookInstallResult {
    Unavailable,
    Partial,
    Active
};

// Calls curl_global_init_mem exactly once per process. Existing host
// initialization can make the hooks unavailable; that must not block transport.
[[nodiscard]] bool EnsureCurlGlobalZapped(const CurlApi& api) noexcept;
[[nodiscard]] GlobalAllocatorHookInstallResult InstallGlobalAllocatorHooks(
    const CurlApi& api) noexcept;
[[nodiscard]] GlobalAllocatorHookInstallResult InstallLinkedGlobalAllocatorHooks() noexcept;

std::unique_ptr<CurlSession> CreateCurlSession(const ClientConfig& config, ErrorCode* init_error);

} // namespace burner::net
