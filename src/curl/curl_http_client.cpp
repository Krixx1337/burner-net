#if BURNER_ENABLE_CURL

#include "curl_http_client.h"

#include "curl_http_client_internal.h"
#include "curl_session.h"
#include "transport_orchestrator.h"
#include "burner/net/detail/dark_arithmetic.h"
#include "burner/net/detail/wiping_alloc_engine.h"
#include "burner/net/obfuscation.h"
#include "internal/openssl_sync.h"
#include "../internal/header_validation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <thread>

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#endif

namespace burner::net {

namespace detail {

bool WouldExceedBodyLimit(std::size_t current_size, std::size_t chunk_size, std::size_t max_body_bytes) noexcept {
    if (max_body_bytes == 0) {
        return false;
    }

    return current_size > max_body_bytes || chunk_size > (max_body_bytes - current_size);
}

namespace {

bool CopyPeerAddress(
    std::string_view remote_ip,
    std::array<char, INET6_ADDRSTRLEN>& buffer) noexcept {
    if (remote_ip.empty() ||
        remote_ip.size() >= buffer.size() ||
        remote_ip.find('\0') != std::string_view::npos) {
        return false;
    }

    std::memcpy(buffer.data(), remote_ip.data(), remote_ip.size());
    buffer[remote_ip.size()] = '\0';
    return true;
}

bool ParseNumericAddress(int family, const char* text, void* output) noexcept {
#ifdef _WIN32
    return InetPtonA(family, text, output) == 1;
#else
    return inet_pton(family, text, output) == 1;
#endif
}

bool BytesAreZero(const std::uint8_t* bytes, std::size_t count) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

} // namespace

PeerAddressClassification ClassifyConnectedPeerAddress(
    const ConnectedPeer& peer) noexcept {
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (!CopyPeerAddress(peer.remote_ip, buffer)) {
        return PeerAddressClassification::Invalid;
    }

    if (peer.address_family == ConnectedPeerAddressFamily::IPv4) {
        in_addr address{};
        if (!ParseNumericAddress(AF_INET, buffer.data(), &address)) {
            return PeerAddressClassification::Invalid;
        }

        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&address);
        return bytes[0] == 127
            ? PeerAddressClassification::Loopback
            : PeerAddressClassification::NonLoopback;
    }

    if (peer.address_family == ConnectedPeerAddressFamily::IPv6) {
        in6_addr address{};
        if (!ParseNumericAddress(AF_INET6, buffer.data(), &address)) {
            return PeerAddressClassification::Invalid;
        }

        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&address);
        const bool ipv6_loopback =
            BytesAreZero(bytes, 15) && bytes[15] == 1;
        const bool ipv4_mapped_loopback =
            BytesAreZero(bytes, 10) &&
            bytes[10] == 0xff &&
            bytes[11] == 0xff &&
            bytes[12] == 127;
        const bool ipv4_compatible_loopback =
            BytesAreZero(bytes, 12) && bytes[12] == 127;

        return ipv6_loopback ||
                ipv4_mapped_loopback ||
                ipv4_compatible_loopback
            ? PeerAddressClassification::Loopback
            : PeerAddressClassification::NonLoopback;
    }

    return PeerAddressClassification::Invalid;
}

DarkString MakeCacheExpiringResolveEntry(std::string_view entry) {
    DarkString expiring_entry;
    if (entry.empty()) {
        return expiring_entry;
    }

    expiring_entry.reserve(entry.size() + 1);
    if (entry.front() != '+') {
        expiring_entry.push_back('+');
    }
    expiring_entry.append(entry.data(), entry.size());
    return expiring_entry;
}

} // namespace detail

namespace {

bool RequestBodyTooLargeForCurl(std::size_t body_size) {
    return body_size > static_cast<std::size_t>((std::numeric_limits<curl_off_t>::max)());
}

DarkString BuildHeaderLine(std::string_view name, std::string_view value) {
    DarkString header;
    header.reserve(name.size() + 2 + value.size());
    header.append(name);
    header.append(": ");
    header.append(value);
    return header;
}

struct IsolatedThreadState {
    IsolatedThreadState(HttpRequest request_value,
                        std::optional<DnsStrategy> strategy_value,
                        CurlHttpClient* client_value)
        : request(std::move(request_value)),
          strategy(std::move(strategy_value)),
          client(client_value) {}

    HttpRequest request;
    std::optional<DnsStrategy> strategy;
    HttpResponse response{};
    CurlHttpClient* client = nullptr;
};

struct PendingResponse {
    HttpResponse value;

    [[nodiscard]] HttpResponse Publish() noexcept {
        return std::move(value);
    }
};

} // namespace

CurlHttpClient::CurlHttpClient(const ClientConfig& config)
    : m_config(config) {
    m_session = CreateCurlSession(m_config, &m_init_error);
}

CurlHttpClient::~CurlHttpClient() {
    // Final "burst-and-burn" scrub: wipe a deep region of the stack as the
    // client is torn down, giving a clean slate before the thread returns to
    // the application's general pool.
    ::burner::net::obf::scrub_stack(32768);
}

CurlHttpClient::CurlHttpClient(CurlHttpClient&& other) noexcept
    : m_config(std::move(other.m_config)),
      m_session(std::move(other.m_session)),
      m_init_error(other.m_init_error),
      m_transfer_cancelled(other.m_transfer_cancelled),
      m_connected_peer_rejected(other.m_connected_peer_rejected),
      m_callback_failed(other.m_callback_failed) {
    other.m_init_error = ErrorCode::None;
    other.m_transfer_cancelled = false;
    other.m_connected_peer_rejected = false;
    other.m_callback_failed = false;
}

CurlHttpClient& CurlHttpClient::operator=(CurlHttpClient&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    m_config = std::move(other.m_config);
    m_session = std::move(other.m_session);
    m_init_error = other.m_init_error;
    m_transfer_cancelled = other.m_transfer_cancelled;
    m_connected_peer_rejected = other.m_connected_peer_rejected;
    m_callback_failed = other.m_callback_failed;

    other.m_init_error = ErrorCode::None;
    other.m_transfer_cancelled = false;
    other.m_connected_peer_rejected = false;
    other.m_callback_failed = false;
    return *this;
}

int CurlHttpClient::PrereqCallback(
    void* clientp,
    char* conn_primary_ip,
    char* conn_local_ip,
    int conn_primary_port,
    int conn_local_port) {
    (void)conn_local_ip;
    (void)conn_local_port;

    auto* self = static_cast<CurlHttpClient*>(clientp);
    if (self == nullptr) {
        return CURL_PREREQFUNC_ABORT;
    }
    if (!self->m_config.reject_loopback_peers &&
        !self->m_config.connected_peer_guard) {
        return CURL_PREREQFUNC_OK;
    }
    if (conn_primary_ip == nullptr) {
        if (self->m_config.reject_loopback_peers) {
            self->m_connected_peer_rejected = true;
            return CURL_PREREQFUNC_ABORT;
        }
        return CURL_PREREQFUNC_OK;
    }

    const ConnectedPeer peer{
        .remote_ip = conn_primary_ip,
        .address_family = std::strchr(conn_primary_ip, ':') != nullptr
            ? ConnectedPeerAddressFamily::IPv6
            : ConnectedPeerAddressFamily::IPv4,
        .remote_port = conn_primary_port,
    };

    if (self->m_config.reject_loopback_peers &&
        detail::ClassifyConnectedPeerAddress(peer) !=
            detail::PeerAddressClassification::NonLoopback) {
        self->m_connected_peer_rejected = true;
        return CURL_PREREQFUNC_ABORT;
    }

    if (!self->m_config.connected_peer_guard) {
        return CURL_PREREQFUNC_OK;
    }

    try {
        if (self->m_config.connected_peer_guard(peer)) {
            return CURL_PREREQFUNC_OK;
        }
        self->m_connected_peer_rejected = true;
        return CURL_PREREQFUNC_ABORT;
    } catch (...) {
        self->m_callback_failed = true;
        return CURL_PREREQFUNC_ABORT;
    }
}

HttpResponse CurlHttpClient::Send(const HttpRequest& request) {
    try {
    if (request.on_chunk_received && m_config.response_verifier) {
        HttpResponse response{};
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::UnsupportedVerifiedStreaming;
        response.verification_status = VerificationStatus::Failed;
        response.verification_error = ErrorCode::UnsupportedVerifiedStreaming;
        return response;
    }

    TransportOrchestrator orchestrator(*this);
    PendingResponse pending{orchestrator.Execute(request)};
    HttpResponse& response = pending.value;

    if (response.TransportOk() && m_config.response_verifier) {
        VerificationResult result{ErrorCode::VerifyGeneric};
        try {
            result = m_config.response_verifier(request, HttpResponseView(response));
        } catch (...) {
            result.error = ErrorCode::CallbackFailed;
        }
        response.verification_status = result.Passed()
            ? VerificationStatus::Passed
            : VerificationStatus::Failed;
        if (!result.Passed()) {
            response.verification_error = result.error;
            WipeResponse(response);
            return pending.Publish();
        }
    }

    if (m_config.require_response_verification &&
        response.verification_status == VerificationStatus::NotConfigured) {
        response.verification_status = VerificationStatus::Failed;
        response.verification_error = ErrorCode::VerifyGeneric;
        WipeResponse(response);
        return pending.Publish();
    }

    return pending.Publish();
    } catch (const std::bad_alloc&) {
        HttpResponse response{};
        response.transport_code = static_cast<int>(CURLE_OUT_OF_MEMORY);
        response.transport_error = ErrorCode::OutOfMemory;
        return response;
    } catch (...) {
        HttpResponse response{};
        response.transport_code = static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
        response.transport_error = ErrorCode::CallbackFailed;
        return response;
    }
}

bool CurlHttpClient::IsInitialized() const {
    return m_session != nullptr && m_session->IsInitialized();
}

HttpResponse CurlHttpClient::PerformOnceInternal(
    const HttpRequest& request,
    const std::optional<DnsStrategy>& strategy) {
    HttpResponse response{};

    auto* easy = m_session ? m_session->EasyHandle() : nullptr;
    if (easy == nullptr) {
        response.transport_code = static_cast<int>(CURLE_FAILED_INIT);
        response.transport_error = ErrorCode::NoCurlHandle;
        return response;
    }
    struct EasyResetGuard final {
        CurlSession* session;
        ~EasyResetGuard() {
            if (session != nullptr) {
                session->Reset();
            }
        }
    } reset_guard{m_session.get()};

    if (request.timeout_seconds < 0 || request.connect_timeout_seconds < 0) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::CurlOptionFailed;
        return response;
    }
    const std::size_t request_body_size = request.stream_payload_provider
        ? request.streamed_payload_size
        : (request.body_view.empty() ? request.body.size() : request.body_view.size());
    if (request.stream_payload_provider && request.method != HttpMethod::Post) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::UnsupportedStreamedMethod;
        return response;
    }
    if (RequestBodyTooLargeForCurl(request_body_size)) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::RequestBodyTooLarge;
        return response;
    }

    char error_buffer[CURL_ERROR_SIZE] = {0};
    auto wipe_error_buffer = [&]() {
#if defined(_WIN32)
        SecureZeroMemory(error_buffer, sizeof(error_buffer));
#else
        volatile char* ptr = error_buffer;
        for (size_t i = 0; i < sizeof(error_buffer); ++i) {
            ptr[i] = '\0';
        }
#endif
    };

    BodyWriteContext body_ctx{};
    body_ctx.body = &response.body;
    body_ctx.callback_failed = &m_callback_failed;
    body_ctx.max_body_bytes = request.max_body_bytes;
    if (m_config.global_max_body_bytes != 0) {
        body_ctx.max_body_bytes =
            body_ctx.max_body_bytes == 0
                ? m_config.global_max_body_bytes
                : (std::min)(body_ctx.max_body_bytes, m_config.global_max_body_bytes);
    }
    body_ctx.on_chunk_received = request.on_chunk_received;
    BodyReadContext read_ctx{};
    read_ctx.provider = &request.stream_payload_provider;
    read_ctx.callback_failed = &m_callback_failed;
    HeaderWriteContext header_ctx{};
    header_ctx.headers = &response.headers;
    header_ctx.callback_failed = &m_callback_failed;

    DarkString protocol_scheme;
    DarkString redirect_protocol_scheme;
    DarkString custom_user_agent;
    DarkString custom_method;
    DarkString cert_type;
    DarkString key_type;

    m_transfer_cancelled = false;
    m_connected_peer_rejected = false;
    m_callback_failed = false;
    m_session->Reset();
    ErrorCode option_error = ApplyCommonOptions(
        request,
        error_buffer,
        &body_ctx,
        &header_ctx,
        &protocol_scheme,
        &redirect_protocol_scheme,
        &custom_user_agent,
        strategy);
    if (option_error == ErrorCode::None) {
        option_error = ApplyMethodAndBody(request, &custom_method, &read_ctx);
    }
    if (option_error == ErrorCode::None) {
        option_error = ApplyTlsOptions(&cert_type, &key_type);
    }
    if (option_error != ErrorCode::None) {
        response.transport_code = option_error == ErrorCode::OutOfMemory
            ? static_cast<int>(CURLE_OUT_OF_MEMORY)
            : static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = option_error;
        wipe_error_buffer();
        return response;
    }

    const CurlApi& curl_api = m_session->Api();
    curl_slist* headers = nullptr;
    for (const auto& [name, value] : m_config.default_headers) {
        if (!internal::IsValidHeaderName(name) || !internal::IsValidHeaderValue(value)) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::InvalidHeader;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        DarkString header = BuildHeaderLine(name, value);
        curl_slist* const appended = curl_api.slist_append(headers, header.c_str());
        SecureWipe(header);
        if (appended == nullptr) {
            response.transport_code = static_cast<int>(CURLE_OUT_OF_MEMORY);
            response.transport_error = ErrorCode::OutOfMemory;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        headers = appended;
    }
    for (const auto& [name, value] : request.headers) {
        if (!internal::IsValidHeaderName(name) || !internal::IsValidHeaderValue(value)) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::InvalidHeader;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        DarkString header = BuildHeaderLine(name, value);
        curl_slist* const appended = curl_api.slist_append(headers, header.c_str());
        SecureWipe(header);
        if (appended == nullptr) {
            response.transport_code = static_cast<int>(CURLE_OUT_OF_MEMORY);
            response.transport_error = ErrorCode::OutOfMemory;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        headers = appended;
    }

    DarkString active_bearer_token;
    bool token_provider_ok = true;
    try {
        if (request.bearer_token_provider) {
            token_provider_ok = request.bearer_token_provider(active_bearer_token);
        } else if (m_config.bearer_token_provider) {
            token_provider_ok = m_config.bearer_token_provider(active_bearer_token);
        }
    } catch (...) {
        token_provider_ok = false;
    }

    const std::string_view active_bearer = active_bearer_token;
    const bool has_secure_token = static_cast<bool>(request.bearer_token_provider) ||
        static_cast<bool>(m_config.bearer_token_provider);
    if (has_secure_token &&
        (!token_provider_ok || !internal::IsValidBearerToken(active_bearer))) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = token_provider_ok
            ? ErrorCode::InvalidCredentials
            : ErrorCode::CredentialProviderFailed;
        SecureWipe(active_bearer_token);
        WipeHeaderList(headers);
        wipe_error_buffer();
        return response;
    }
    if (request.follow_redirects && has_secure_token) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::RedirectAuth;
        SecureWipe(active_bearer_token);
        WipeHeaderList(headers);
        wipe_error_buffer();
        return response;
    }

    if (!active_bearer.empty()) {
        DarkString auth_prefix(BURNER_OBF_LITERAL("Authorization: Bearer "));
    DarkString auth;
        auth.reserve(auth_prefix.size() + active_bearer.size());
        auth.append(auth_prefix);
        auth.append(active_bearer.data(), active_bearer.size());
        SecureWipe(auth_prefix);
        curl_slist* const appended = curl_api.slist_append(headers, auth.c_str());
        SecureWipe(auth);
        if (appended == nullptr) {
            response.transport_code = static_cast<int>(CURLE_OUT_OF_MEMORY);
            response.transport_error = ErrorCode::OutOfMemory;
            SecureWipe(active_bearer_token);
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        headers = appended;
    }
    SecureWipe(active_bearer_token);

    if (headers != nullptr) {
        if (curl_api.easy_setopt(
                easy,
                static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_HTTPHEADER))),
                headers) != CURLE_OK) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::CurlOptionFailed;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
    }

    curl_slist* bootstrap_resolve_entries = nullptr;
    if (strategy.has_value() &&
        strategy->mode == DnsMode::Doh &&
        !strategy->bootstrap_resolve_entry.empty()) {
        DarkString expiring_bootstrap_entry =
            detail::MakeCacheExpiringResolveEntry(strategy->bootstrap_resolve_entry);
        bootstrap_resolve_entries =
            curl_api.slist_append(nullptr, expiring_bootstrap_entry.c_str());
        SecureWipe(expiring_bootstrap_entry);
        if (bootstrap_resolve_entries == nullptr) {
            response.transport_code = static_cast<int>(CURLE_OUT_OF_MEMORY);
            response.transport_error = ErrorCode::OutOfMemory;
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
        if (curl_api.easy_setopt(
            easy,
            static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_RESOLVE))),
            bootstrap_resolve_entries) != CURLE_OK) {
            response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
            response.transport_error = ErrorCode::CurlOptionFailed;
            WipeHeaderList(bootstrap_resolve_entries);
            WipeHeaderList(headers);
            wipe_error_buffer();
            return response;
        }
    }

    if (curl_api.easy_setopt(
        easy,
        static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PREREQFUNCTION))),
        &CurlHttpClient::PrereqCallback) != CURLE_OK ||
        curl_api.easy_setopt(
        easy,
        static_cast<CURLoption>(BURNER_MASK_INT(static_cast<long>(CURLOPT_PREREQDATA))),
        this) != CURLE_OK) {
        response.transport_code = static_cast<int>(CURLE_BAD_FUNCTION_ARGUMENT);
        response.transport_error = ErrorCode::CurlOptionFailed;
        WipeHeaderList(bootstrap_resolve_entries);
        WipeHeaderList(headers);
        wipe_error_buffer();
        return response;
    }
    const CURLcode code = curl_api.easy_perform(easy);
    WipeHeaderList(bootstrap_resolve_entries);

    // Wipe the stack region used by the transport chain (TLS keys, header
    // fragments, session state) before any other logic can read it.
    ::burner::net::obf::scrub_stack(16384);

    SecureWipe(protocol_scheme);
    SecureWipe(redirect_protocol_scheme);
    SecureWipe(custom_user_agent);
    SecureWipe(custom_method);
    SecureWipe(cert_type);
    SecureWipe(key_type);

    response.transport_code = static_cast<int>(code);
    if (code != CURLE_OK) {
        if (code == CURLE_OUT_OF_MEMORY) {
            response.transport_error = ErrorCode::OutOfMemory;
        } else if (code == CURLE_PEER_FAILED_VERIFICATION
#ifdef CURLE_SSL_CACERT
            || code == CURLE_SSL_CACERT
#endif
        ) {
            response.transport_error = ErrorCode::TlsVerificationFailed;
        } else if (m_callback_failed) {
            response.transport_error = ErrorCode::CallbackFailed;
        } else if (code == CURLE_ABORTED_BY_CALLBACK && m_connected_peer_rejected) {
            response.transport_error = ErrorCode::TransportVerificationFailed;
        } else if (code == CURLE_WRITE_ERROR && body_ctx.limit_exceeded) {
            response.transport_error = ErrorCode::BodyTooLarge;
        } else if (code == CURLE_ABORTED_BY_CALLBACK && m_transfer_cancelled) {
            response.transport_error = ErrorCode::TransferCancelled;
        } else if (code == CURLE_COULDNT_RESOLVE_HOST) {
            response.transport_error = ErrorCode::DnsResolutionFailed;
        } else if (code == CURLE_COULDNT_CONNECT) {
            response.transport_error = ErrorCode::ConnectFailed;
        } else if (code == CURLE_OPERATION_TIMEDOUT) {
            response.transport_error = ErrorCode::TimedOut;
        } else {
            response.transport_error = ErrorCode::CurlGeneric;
        }
        WipeResponse(response);
    }

    if (response.TransportOk()) {
        double total_time = 0.0;
        if (curl_api.easy_getinfo(
                easy,
                static_cast<CURLINFO>(BURNER_MASK_INT(static_cast<long>(CURLINFO_TOTAL_TIME))),
                &total_time) == CURLE_OK) {
            response.telemetry.total_time_seconds = total_time;
        }

        curl_certinfo* cert_info = nullptr;
        if (curl_api.easy_getinfo(
                easy,
                static_cast<CURLINFO>(BURNER_MASK_INT(static_cast<long>(CURLINFO_CERTINFO))),
                &cert_info) == CURLE_OK &&
            cert_info != nullptr) {
            for (int cert_index = 0; cert_index < cert_info->num_of_certs; ++cert_index) {
                for (curl_slist* line = cert_info->certinfo[cert_index]; line != nullptr; line = line->next) {
                    if (line->data != nullptr) {
                        response.telemetry.tls_chain.emplace_back(line->data);
                    }
                }
            }
        }

    }

    response.dns_strategy_used = strategy.has_value() ? strategy->name : DarkString{};
    response.streamed_body_bytes = body_ctx.streamed_body_bytes;

    curl_api.easy_getinfo(easy, static_cast<CURLINFO>(BURNER_MASK_INT(static_cast<long>(CURLINFO_RESPONSE_CODE))), &response.status_code);

    if (headers != nullptr) {
        WipeHeaderList(headers);
    }

    wipe_error_buffer();
    return response;
}

HttpResponse CurlHttpClient::PerformOnce(HttpRequest request, std::optional<DnsStrategy> strategy) {
    // Fast-path: If isolation is disabled, execute on the caller's thread.
    if (!m_config.enable_stack_isolation) {
        return PerformOnceInternal(request, strategy);
    }

    std::unique_ptr<IsolatedThreadState> state;
    try {
        state = std::make_unique<IsolatedThreadState>(
            std::move(request), std::move(strategy), this);
    } catch (...) {
        HttpResponse response{};
        response.transport_code = static_cast<int>(CURLE_OUT_OF_MEMORY);
        response.transport_error = ErrorCode::OutOfMemory;
        return response;
    }

    std::thread worker;
    try {
        worker = std::thread([state_ptr = state.get()]() noexcept {
            try {
                state_ptr->response = state_ptr->client->PerformOnceInternal(
                    state_ptr->request, state_ptr->strategy);
            } catch (...) {
                state_ptr->response.transport_code =
                    static_cast<int>(CURLE_ABORTED_BY_CALLBACK);
                state_ptr->response.transport_error = ErrorCode::CallbackFailed;
            }
            TryInvokeOpenSSLThreadStop();
        });
    } catch (...) {
        HttpResponse response{};
        response.transport_code = static_cast<int>(CURLE_FAILED_INIT);
        response.transport_error = ErrorCode::WorkerThreadStartFailed;
        return response;
    }

    worker.join();

    HttpResponse response = std::move(state->response);

    // Final hygiene: Wipe the caller's stack frame just in case any
    // pointer residue was left during the handoff or thread setup.
    ::burner::net::obf::scrub_stack(1024);

    return response;
}

bool CurlHttpClient::ShouldRetry(const HttpRequest& request, const HttpResponse& response, int attempt) const {
    const int attempts = (std::max)(1, request.retry.max_attempts);
    if (attempt >= attempts) {
        return false;
    }

    if (!response.TransportOk() &&
        request.retry.retry_on_transport_error &&
        IsRetryable(response.transport_error)) {
        return true;
    }

    if (response.TransportOk() && request.retry.retry_on_5xx && response.status_code >= 500 && response.status_code < 600) {
        return true;
    }

    return false;
}

bool CurlHttpClient::IsRetryable(ErrorCode error) const noexcept {
    switch (error) {
    case ErrorCode::DnsResolutionFailed:
    case ErrorCode::ConnectFailed:
    case ErrorCode::TimedOut:
        return true;
    default:
        return false;
    }
}

} // namespace burner::net

#endif
