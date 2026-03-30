#include <doctest/doctest.h>

#include <string>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"
#include "burner/net/signature_verifier.h"
#include "internal/header_validation.h"

TEST_CASE("header validation rejects CRLF injection") {
    CHECK_FALSE(burner::net::internal::IsValidHeaderName("Content-Type\r\nSet-Cookie: pwned=1"));
    CHECK_FALSE(burner::net::internal::IsValidHeaderValue("Bearer abc\nX-Injected: true"));
}

TEST_CASE("header validation accepts ordinary header tokens") {
    CHECK(burner::net::internal::IsValidHeaderName("X-Custom-Header"));
    CHECK(burner::net::internal::IsValidHeaderName("Authorization"));
    CHECK(burner::net::internal::IsValidHeaderValue("Bearer abc.def"));
}

TEST_CASE("obfuscation helper returns expected plaintext") {
    const std::string value = BURNER_OBF_LITERAL("test");
    CHECK(value == "test");

#if BURNERNET_OBFUSCATE_STRINGS
    std::string wiped = value;
    burner::net::SecureWipe(wiped);
    CHECK(wiped.empty());
#endif
}

TEST_CASE("hmac verifier accepts known valid signature") {
    burner::net::HttpResponse response{};
    response.body = "payload";
    response.headers["x-signature"] =
        "b82fcb791acec57859b989b430a826488ce2e479fdf92326bd0a2e8375a42ba4";

    burner::net::SignatureVerifierConfig config{};
    config.signature_header = "x-signature";
    config.secret = "secret";
    burner::net::HmacSha256HeaderVerifier verifier(config);

    burner::net::ErrorCode reason = burner::net::ErrorCode::None;
    CHECK(verifier.Verify(burner::net::HttpRequest{}, response, &reason));
    CHECK(reason == burner::net::ErrorCode::None);
}

TEST_CASE("hmac verifier rejects mismatched signature") {
    burner::net::HttpResponse response{};
    response.body = "payload";
    response.headers["x-signature"] = "deadbeef";

    burner::net::SignatureVerifierConfig config{};
    config.signature_header = "x-signature";
    config.secret = "secret";
    burner::net::HmacSha256HeaderVerifier verifier(config);

    burner::net::ErrorCode reason = burner::net::ErrorCode::None;
    CHECK_FALSE(verifier.Verify(burner::net::HttpRequest{}, response, &reason));
    CHECK(reason == burner::net::ErrorCode::SigMismatch);
}

TEST_CASE("error codes map to expected output based on hardening") {
#if BURNERNET_HARDEN_ERRORS
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::DisabledBackend) ==
          std::to_string(static_cast<uint32_t>(burner::net::ErrorCode::DisabledBackend) ^
                         burner::net::detail::ErrorXorKey()));
#else
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::DisabledBackend) == "DisabledBackend");
#endif
}

TEST_CASE("pre-flight abort error code string is stable") {
#if BURNERNET_HARDEN_ERRORS
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::PreFlightAbort) ==
          std::to_string(static_cast<uint32_t>(burner::net::ErrorCode::PreFlightAbort) ^
                         burner::net::detail::ErrorXorKey()));
#else
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::PreFlightAbort) == "PreFlightAbort");
#endif
}

TEST_CASE("environment compromised error code string is stable") {
#if BURNERNET_HARDEN_ERRORS
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::EnvironmentCompromised) ==
          std::to_string(static_cast<uint32_t>(burner::net::ErrorCode::EnvironmentCompromised) ^
                         burner::net::detail::ErrorXorKey()));
#else
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::EnvironmentCompromised) ==
          "EnvironmentCompromised");
#endif
}

TEST_CASE("transport verification failed error code string is stable") {
#if BURNERNET_HARDEN_ERRORS
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::TransportVerificationFailed) ==
          std::to_string(static_cast<uint32_t>(burner::net::ErrorCode::TransportVerificationFailed) ^
                         burner::net::detail::ErrorXorKey()));
#else
    CHECK(burner::net::ErrorCodeToString(burner::net::ErrorCode::TransportVerificationFailed) ==
          "TransportVerificationFailed");
#endif
}
