#include <doctest/doctest.h>

#include <string>
#include <utility>

#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"
#include "burner/net/signature_verifier.h"
#include "curl/curl_http_client.h"
#include "internal/import_pointer_trust.h"
#include "internal/header_validation.h"

#ifdef _WIN32
#include <windows.h>
#endif

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

TEST_CASE("header map preserves unique keys and treats names as case-insensitive") {
    burner::net::HeaderMap headers;
    headers["Authorization"] = "Bearer one";
    headers.insert_or_assign("Authorization", "Bearer two");
    headers.insert_or_assign("X-Test", "value");
    headers.insert_or_assign("content-type", "application/json");
    headers.insert_or_assign("Content-Type", "text/plain");

    CHECK(headers.size() == 3);

    auto it = headers.begin();
    REQUIRE(it != headers.end());
    CHECK(it->first == "Authorization");
    CHECK(it->second == "Bearer two");
    CHECK(headers["CONTENT-TYPE"] == "text/plain");
}

TEST_CASE("body limit helper rejects chunks that exceed max body bytes") {
    CHECK_FALSE(burner::net::detail::WouldExceedBodyLimit(0, 10, 10));
    CHECK(burner::net::detail::WouldExceedBodyLimit(10, 1, 10));
    CHECK(burner::net::detail::WouldExceedBodyLimit(5, 6, 10));
}

TEST_CASE("import pointer trust accepts allowed system module and rejects wrong one") {
#ifdef _WIN32
    const auto* fn_ptr = reinterpret_cast<const void*>(&GetModuleHandleA);

    CHECK(burner::net::internal::IsFunctionPointerInAllowedModules(
        fn_ptr,
        {L"kernel32.dll"}));
    CHECK_FALSE(burner::net::internal::IsFunctionPointerInAllowedModules(
        fn_ptr,
        {L"malicious.dll"}));
    CHECK(burner::net::internal::IsFunctionPointerExecutable(fn_ptr));
    CHECK(burner::net::internal::IsFunctionPointerTrusted(
        fn_ptr,
        {L"kernel32.dll"}));
    CHECK_FALSE(burner::net::internal::IsFunctionPointerTrusted(
        fn_ptr,
        {L"malicious.dll"}));
#else
    MESSAGE("Import pointer trust is Windows-only.");
    CHECK(true);
#endif
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

TEST_CASE("selected error code strings are stable") {
    const burner::net::ErrorCode codes[] = {
        burner::net::ErrorCode::PreFlightAbort,
        burner::net::ErrorCode::EnvironmentCompromised,
        burner::net::ErrorCode::TransportVerificationFailed,
    };

    for (const auto code : codes) {
#if BURNERNET_HARDEN_ERRORS
        CHECK(burner::net::ErrorCodeToString(code) ==
              std::to_string(static_cast<uint32_t>(code) ^ burner::net::detail::ErrorXorKey()));
#else
        if (code == burner::net::ErrorCode::PreFlightAbort) {
            CHECK(burner::net::ErrorCodeToString(code) == "PreFlightAbort");
        } else if (code == burner::net::ErrorCode::EnvironmentCompromised) {
            CHECK(burner::net::ErrorCodeToString(code) == "EnvironmentCompromised");
        } else if (code == burner::net::ErrorCode::TransportVerificationFailed) {
            CHECK(burner::net::ErrorCodeToString(code) == "TransportVerificationFailed");
        } else {
            FAIL("Unexpected error code in stability test");
        }
#endif
    }
}
