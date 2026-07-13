#pragma once

#include "burner/net/builder.h"

namespace burner::net {

class BURNER_API Client final {
public:
    Client();
    ~Client() = default;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    [[nodiscard]] bool IsReady() const noexcept { return m_init_error == ErrorCode::None; }
    [[nodiscard]] ErrorCode InitError() const noexcept { return m_init_error; }

    [[nodiscard]] RequestBuilder<CurlHttpClient> Get(std::string url) { return m_client.Get(std::move(url)); }
    [[nodiscard]] RequestBuilder<CurlHttpClient> Post(std::string url) { return m_client.Post(std::move(url)); }
    [[nodiscard]] RequestBuilder<CurlHttpClient> Put(std::string url) { return m_client.Put(std::move(url)); }
    [[nodiscard]] RequestBuilder<CurlHttpClient> Delete(std::string url) { return m_client.Delete(std::move(url)); }
    [[nodiscard]] RequestBuilder<CurlHttpClient> Patch(std::string url) { return m_client.Patch(std::move(url)); }

private:
    explicit Client(CurlHttpClient transport);

    ErrorCode m_init_error = ErrorCode::None;
    FluentClient<CurlHttpClient> m_client;
};

} // namespace burner::net
