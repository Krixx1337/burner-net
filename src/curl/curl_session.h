#pragma once

#include "curl_api.h"
#include "burner/net/http.h"
#include "burner/net/policy.h"

#include <memory>

namespace burner::net {

class CurlSession {
public:
    explicit CurlSession(CurlApi api);
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
    CurlApi m_api;
    CURL* m_easy = nullptr;
};

// Calls curl_global_init_mem exactly once per process, injecting the wiping
// allocator callbacks.  Must be called after the CurlApi is fully populated
// and before easy_init() is invoked.
void EnsureCurlGlobalZapped(const CurlApi& api, const SecurityPolicy& policy) noexcept;

std::unique_ptr<CurlSession> CreateCurlSession(const ClientConfig& config, ErrorCode* init_error);

} // namespace burner::net
