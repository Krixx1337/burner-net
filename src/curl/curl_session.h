#pragma once

#include "curl_api.h"
#include "burner/net/http.h"

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

std::unique_ptr<CurlSession> CreateCurlSession(const ClientConfig& config, ErrorCode* init_error);

} // namespace burner::net
