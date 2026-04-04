#pragma once

#include <concepts>
#include <cstdint>

namespace burner::net {

enum class ErrorCode : std::uint32_t;
struct TransportTelemetry;
struct HttpRequest;
struct HttpResponse;
struct TransferProgress;

template <typename T>
concept SecurityPolicyConcept = requires(const T policy, HttpRequest& request, const HttpRequest& const_request,
    const HttpResponse& response, const TransportTelemetry& telemetry, const TransferProgress& progress,
    bool verified, ErrorCode reason, const char* url, const char* remote_ip) {
    { policy.OnVerifyEnvironment() } -> std::convertible_to<bool>;
    { policy.OnPreRequest(request) } -> std::convertible_to<bool>;
    { policy.OnVerifyTransport(url, remote_ip) } -> std::convertible_to<bool>;
    { policy.OnAuditTelemetry(telemetry) } -> std::convertible_to<bool>;
    { policy.OnHeartbeat(progress) } -> std::convertible_to<bool>;
    { policy.OnResponseReceived(const_request, response) } -> std::convertible_to<bool>;
    { policy.OnSignatureVerified(verified, reason) } -> std::same_as<void>;
    { policy.OnTamper() } -> std::same_as<void>;
    { policy.OnError(reason, url) } -> std::same_as<void>;
    { policy.OnIsolatedWorkerStart() } -> std::convertible_to<bool>;
    { policy.OnIsolatedWorkerEnd() } -> std::same_as<void>;
    { policy.GetUserAgent() };
};

template <typename T>
concept ResponseVerifierConcept = requires(T verifier, const HttpRequest& request, const HttpResponse& response, ErrorCode* reason) {
    { verifier.Verify(request, response, reason) } -> std::convertible_to<bool>;
};

template <typename T>
concept HttpClientConcept = requires(T client, const HttpRequest& request) {
    { client.Send(request) };
};

} // namespace burner::net
