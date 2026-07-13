#include "burner/net/client.h"

namespace burner::net {

namespace {

ClientConfig MakeStandardConfig() {
    ClientConfig config{};
    config.use_native_ca = true;
    config.use_system_proxy = true;
    config.verify_peer = true;
    config.verify_host = true;
    return config;
}

} // namespace

Client::Client()
    : Client(CurlHttpClient(MakeStandardConfig())) {}

Client::Client(CurlHttpClient transport)
    : m_init_error(transport.InitError()),
      m_client(std::move(transport), DnsFallbackPolicy{}, m_init_error) {}

} // namespace burner::net
