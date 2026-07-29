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
concept HttpClientConcept = requires(T client, const HttpRequest& request) {
    { client.Send(request) };
};

} // namespace burner::net
