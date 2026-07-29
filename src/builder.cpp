#include "burner/net/builder.h"

#include "curl/curl_http_client.h"
#include "internal/header_validation.h"

#include <array>
#include <new>

namespace burner::net {

namespace detail {

bool IsValidInlineSha256Pin(std::string_view pin) noexcept {
    constexpr std::string_view prefix = "sha256//";
    if (!pin.starts_with(prefix)) {
        return false;
    }
    pin.remove_prefix(prefix.size());
    if (pin.size() != 44 || pin.back() != '=') {
        return false;
    }

    auto base64_value = [](char ch) noexcept -> int {
        if (ch >= 'A' && ch <= 'Z') return ch - 'A';
        if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
        if (ch >= '0' && ch <= '9') return ch - '0' + 52;
        if (ch == '+') return 62;
        if (ch == '/') return 63;
        return -1;
    };

    std::array<unsigned char, 32> decoded{};
    std::size_t out = 0;
    unsigned int accumulator = 0;
    int bits = 0;
    for (std::size_t i = 0; i + 1 < pin.size(); ++i) {
        const int value = base64_value(pin[i]);
        if (value < 0) {
            return false;
        }
        accumulator = (accumulator << 6) | static_cast<unsigned int>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out >= decoded.size()) {
                return false;
            }
            decoded[out++] = static_cast<unsigned char>((accumulator >> bits) & 0xffu);
        }
    }
    return out == decoded.size() && bits == 2 && (accumulator & 0x3u) == 0;
}

} // namespace detail

ClientBuilder::ClientBuilder()
    : ClientBuilder(ClientProfile::Standard) {}

ClientBuilder::ClientBuilder(ClientProfile profile)
    : m_profile(profile) {
    m_config.use_native_ca = true;
    m_config.verify_peer = true;
    m_config.verify_host = true;
    m_config.use_system_proxy = profile == ClientProfile::Standard;
    m_config.enable_stack_isolation = profile == ClientProfile::Hardened;
}

ClientBuilder& ClientBuilder::WithUserAgent(std::string user_agent) {
    m_config.user_agent = std::move(user_agent);
    return *this;
}

ClientBuilder& ClientBuilder::WithVerifyPeer(bool enabled) {
    m_config.verify_peer = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithVerifyHost(bool enabled) {
    m_config.verify_host = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithUseNativeCa(bool enabled) {
    m_config.use_native_ca = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithMtlsProvider(detail::CompactCallable<bool(MtlsCredentials&)> provider) {
    m_config.mtls_provider = std::move(provider);
    return *this;
}

ClientBuilder& ClientBuilder::WithBearerTokenProvider(TokenProvider provider) {
    m_config.bearer_token_provider = std::move(provider);
    return *this;
}

ClientBuilder& ClientBuilder::WithRequestGuard(RequestGuard guard) {
    m_config.request_guard = std::move(guard);
    return *this;
}

ClientBuilder& ClientBuilder::WithLoopbackPeerRejection(bool enabled) {
    m_config.reject_loopback_peers = enabled;
    return *this;
}

ClientBuilder& ClientBuilder::WithConnectedPeerGuard(ConnectedPeerGuard guard) {
    m_config.connected_peer_guard = std::move(guard);
    return *this;
}

ClientBuilder& ClientBuilder::WithTransferCancellation(TransferCancellation cancellation) {
    m_config.transfer_cancellation = std::move(cancellation);
    return *this;
}

ClientBuilder& ClientBuilder::WithGlobalMaxBodyLimit(std::size_t max_body_bytes) {
    m_config.global_max_body_bytes = max_body_bytes;
    return *this;
}

ClientBuilder& ClientBuilder::WithCurlModuleName(std::string name) {
    m_config.curl_module_name = std::move(name);
    return *this;
}

ClientBuilder& ClientBuilder::WithCasualDefaults() {
    m_config.use_system_proxy = true;
    m_config.use_native_ca = true;
    m_config.verify_peer = true;
    m_config.verify_host = true;
    return *this;
}

ClientBuilder& ClientBuilder::AllowSystemDns(bool fallback_allowed) {
    if (!fallback_allowed) {
        return *this;
    }

    bool has_system = false;
    for (const auto& strategy : m_default_dns_fallback.strategies) {
        if (strategy.mode == DnsMode::System) {
            has_system = true;
            break;
        }
    }

    if (!has_system) {
        DnsStrategy system_strategy{};
        system_strategy.mode = DnsMode::System;
        system_strategy.name = DarkString(BURNER_OBF_LITERAL("System DNS Insecure"));
        m_default_dns_fallback.strategies.push_back(std::move(system_strategy));
    }
    m_default_dns_fallback.enabled = true;
    m_system_dns_explicit = true;
    return *this;
}

ClientBuilder& ClientBuilder::WithDnsFallback(
    DnsMode mode,
    std::string value,
    std::string name,
    std::string bootstrap_resolve_entry) {
    if (!m_custom_dns_fallback) {
        m_default_dns_fallback.strategies.clear();
        m_system_dns_explicit = false;
        m_custom_dns_fallback = true;
    }

    if (mode == DnsMode::System) {
        m_system_dns_explicit = false;
    }

    DnsStrategy strategy{};
    strategy.mode = mode;
    strategy.doh_url = DarkString(std::move(value));
    if (mode == DnsMode::Doh && !bootstrap_resolve_entry.empty())
        strategy.bootstrap_resolve_entry = DarkString(std::move(bootstrap_resolve_entry));
    if (!name.empty()) {
        strategy.name = DarkString(std::move(name));
    } else if (mode == DnsMode::Doh) {
        strategy.name = DarkString(BURNER_OBF_LITERAL("DoH Custom"));
    } else {
        strategy.name = DarkString(BURNER_OBF_LITERAL("System DNS Insecure"));
    }
    m_default_dns_fallback.enabled = true;
    m_default_dns_fallback.strategies.push_back(std::move(strategy));
    return *this;
}

ClientBuilder& ClientBuilder::WithPinnedKey(std::string pin) {
    m_config.pinned_public_keys.emplace_back(std::move(pin));
    return *this;
}

ClientBuilder& ClientBuilder::WithStackIsolation(bool enabled) {
    m_config.enable_stack_isolation = enabled;
    return *this;
}

ClientBuilder::ClientBuildResult ClientBuilder::Build() {
    try {
    if (m_profile == ClientProfile::Hardened) {
        if (m_config.use_system_proxy) {
            return {nullptr, ErrorCode::HardenedSystemProxyForbidden};
        }
        if (!m_config.verify_peer) {
            return {nullptr, ErrorCode::HardenedVerifyPeerRequired};
        }
        if (!m_config.verify_host) {
            return {nullptr, ErrorCode::HardenedVerifyHostRequired};
        }
        if (!m_config.enable_stack_isolation) {
            return {nullptr, ErrorCode::HardenedStackIsolationRequired};
        }

        bool has_doh = false;
        bool has_system_dns = false;
        bool system_dns_seen = false;
        bool invalid_dns_order = false;
        for (const auto& strategy : m_default_dns_fallback.strategies) {
            if (strategy.mode == DnsMode::System) {
                has_system_dns = true;
                system_dns_seen = true;
            } else {
                has_doh = true;
                if (strategy.mode != DnsMode::Doh ||
                    !internal::IsValidHttpsUrl(strategy.doh_url)) {
                    return {nullptr, ErrorCode::InvalidHardenedDoh};
                }
                if (system_dns_seen) {
                    invalid_dns_order = true;
                }
            }
        }
        if (!has_doh) {
            return {nullptr, ErrorCode::HardenedDohRequired};
        }
        if (invalid_dns_order || (has_system_dns && !m_system_dns_explicit)) {
            return {nullptr, ErrorCode::HardenedSystemDnsOrder};
        }
        if (!m_config.response_verifier) {
            return {nullptr, ErrorCode::HardenedResponseVerifierRequired};
        }
        for (const auto& pin : m_config.pinned_public_keys) {
            if (!detail::IsValidInlineSha256Pin(pin)) {
                return {nullptr, ErrorCode::InvalidHardenedPin};
            }
        }
    }

    ClientConfig config = m_config;
    config.require_response_verification = m_profile == ClientProfile::Hardened;

    CurlHttpClient transport(config);
    if (!transport.IsInitialized()) {
        return {nullptr, transport.InitError()};
    }

    return {std::make_unique<FluentClient<CurlHttpClient>>(
        std::move(transport), m_default_dns_fallback), ErrorCode::None};
    } catch (const std::bad_alloc&) {
        return {nullptr, ErrorCode::OutOfMemory};
    } catch (...) {
        return {nullptr, ErrorCode::CallbackFailed};
    }
}

} // namespace burner::net

