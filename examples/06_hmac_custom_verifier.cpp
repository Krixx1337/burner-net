#include <algorithm>
#include <array>
#include <cctype>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "burner/net/builder.h"
#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/error.h"
#include "burner/net/http.h"
#include "burner/net/obfuscation.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

namespace {

std::string Trim(std::string value) {
    const auto is_ws = [](unsigned char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    };

    while (!value.empty() && is_ws(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }

    std::size_t start = 0;
    while (start < value.size() && is_ws(static_cast<unsigned char>(value[start]))) {
        ++start;
    }

    if (start != 0) {
        value.erase(0, start);
    }

    return value;
}

std::string GetHeaderCaseInsensitive(const burner::net::HeaderMap& headers, std::string_view name) {
    for (const auto& [header_name, value] : headers) {
        if (burner::net::HeaderNameEquals(header_name, name)) {
            return std::string(value);
        }
    }
    return {};
}

#ifdef _WIN32
using BCryptOpenAlgorithmProviderFn = decltype(&BCryptOpenAlgorithmProvider);
using BCryptGetPropertyFn = decltype(&BCryptGetProperty);
using BCryptCreateHashFn = decltype(&BCryptCreateHash);
using BCryptHashDataFn = decltype(&BCryptHashData);
using BCryptFinishHashFn = decltype(&BCryptFinishHash);
using BCryptDestroyHashFn = decltype(&BCryptDestroyHash);
using BCryptCloseAlgorithmProviderFn = decltype(&BCryptCloseAlgorithmProvider);

constexpr std::uint32_t kBcryptHash = burner::net::detail::fnv1a_ci("bcrypt.dll");
constexpr std::uint32_t kBCryptOpenAlgorithmProviderHash =
    burner::net::detail::fnv1a("BCryptOpenAlgorithmProvider");
constexpr std::uint32_t kBCryptGetPropertyHash =
    burner::net::detail::fnv1a("BCryptGetProperty");
constexpr std::uint32_t kBCryptCreateHashHash =
    burner::net::detail::fnv1a("BCryptCreateHash");
constexpr std::uint32_t kBCryptHashDataHash =
    burner::net::detail::fnv1a("BCryptHashData");
constexpr std::uint32_t kBCryptFinishHashHash =
    burner::net::detail::fnv1a("BCryptFinishHash");
constexpr std::uint32_t kBCryptDestroyHashHash =
    burner::net::detail::fnv1a("BCryptDestroyHash");
constexpr std::uint32_t kBCryptCloseAlgorithmProviderHash =
    burner::net::detail::fnv1a("BCryptCloseAlgorithmProvider");

std::string ToLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool ConstantTimeEqual(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    unsigned char diff = 0;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        diff |= static_cast<unsigned char>(lhs[i] ^ rhs[i]);
    }
    return diff == 0;
}

std::string ToHexLower(const unsigned char* bytes, std::size_t len) {
    auto nibble_to_hex = [](unsigned char nibble) -> char {
        nibble &= 0x0F;
        return static_cast<char>(nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
    };

    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[i * 2] = nibble_to_hex(static_cast<unsigned char>((bytes[i] >> 4) & 0x0F));
        out[(i * 2) + 1] = nibble_to_hex(static_cast<unsigned char>(bytes[i] & 0x0F));
    }
    return out;
}

bool ComputeHmacSha256Hex(std::string_view data, std::string_view secret, std::string* out_hex) {
    if (out_hex == nullptr) {
        return false;
    }

    void* const bcrypt_module =
        burner::net::detail::KernelResolver::GetSystemModule(kBcryptHash);
    if (bcrypt_module == nullptr) {
        return false;
    }

    const BCryptOpenAlgorithmProviderFn bcrypt_open_algorithm_provider =
        reinterpret_cast<BCryptOpenAlgorithmProviderFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptOpenAlgorithmProviderHash));
    const BCryptGetPropertyFn bcrypt_get_property =
        reinterpret_cast<BCryptGetPropertyFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptGetPropertyHash));
    const BCryptCreateHashFn bcrypt_create_hash =
        reinterpret_cast<BCryptCreateHashFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptCreateHashHash));
    const BCryptHashDataFn bcrypt_hash_data =
        reinterpret_cast<BCryptHashDataFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptHashDataHash));
    const BCryptFinishHashFn bcrypt_finish_hash =
        reinterpret_cast<BCryptFinishHashFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptFinishHashHash));
    const BCryptDestroyHashFn bcrypt_destroy_hash =
        reinterpret_cast<BCryptDestroyHashFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptDestroyHashHash));
    const BCryptCloseAlgorithmProviderFn bcrypt_close_algorithm_provider =
        reinterpret_cast<BCryptCloseAlgorithmProviderFn>(
            burner::net::detail::KernelResolver::ResolveInternalExport(
                bcrypt_module,
                kBCryptCloseAlgorithmProviderHash));
    if (bcrypt_open_algorithm_provider == nullptr || bcrypt_get_property == nullptr ||
        bcrypt_create_hash == nullptr || bcrypt_hash_data == nullptr ||
        bcrypt_finish_hash == nullptr || bcrypt_destroy_hash == nullptr ||
        bcrypt_close_algorithm_provider == nullptr) {
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD cb_result = 0;

    NTSTATUS status = bcrypt_open_algorithm_provider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) {
        return false;
    }

    status = bcrypt_get_property(
        alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &cb_result, 0);
    if (status < 0 || object_size == 0) {
        bcrypt_close_algorithm_provider(alg, 0);
        return false;
    }

    std::vector<unsigned char> object_buffer(object_size);
    std::array<unsigned char, 32> hash_bytes{};

    const auto cleanup = [&]() {
        burner::net::SecureWipe(object_buffer);
        burner::net::SecureWipe(std::span<unsigned char>(hash_bytes.data(), hash_bytes.size()));
    };

    status = bcrypt_create_hash(
        alg,
        &hash,
        object_buffer.data(),
        static_cast<ULONG>(object_buffer.size()),
        reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
        static_cast<ULONG>(secret.size()),
        0);
    if (status < 0) {
        cleanup();
        bcrypt_close_algorithm_provider(alg, 0);
        return false;
    }

    status = bcrypt_hash_data(
        hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
        static_cast<ULONG>(data.size()),
        0);
    if (status < 0) {
        cleanup();
        bcrypt_destroy_hash(hash);
        bcrypt_close_algorithm_provider(alg, 0);
        return false;
    }

    status = bcrypt_finish_hash(hash, hash_bytes.data(), static_cast<ULONG>(hash_bytes.size()), 0);
    if (status < 0) {
        cleanup();
        bcrypt_destroy_hash(hash);
        bcrypt_close_algorithm_provider(alg, 0);
        return false;
    }

    bcrypt_destroy_hash(hash);
    bcrypt_close_algorithm_provider(alg, 0);
    *out_hex = ToHexLower(hash_bytes.data(), hash_bytes.size());
    cleanup();
    return true;
}
#endif

bool VerifyHmacHeader(
    const burner::net::HttpRequest&,
    const burner::net::HttpResponse& response,
    burner::net::ErrorCode* reason) {
    const std::string signature_header = "X-Auth-Verify";
    burner::net::SecureString secret = "replace-with-a-real-secret";

    if (secret.empty()) {
        if (reason != nullptr) {
            *reason = burner::net::ErrorCode::SigEmpty;
        }
        return false;
    }

    std::string received = Trim(GetHeaderCaseInsensitive(response.headers, signature_header));
    if (received.empty()) {
        burner::net::SecureWipe(secret);
        if (reason != nullptr) {
            *reason = burner::net::ErrorCode::SigHeaderMissing;
        }
        return false;
    }

#ifdef _WIN32
    std::string computed;
    if (!ComputeHmacSha256Hex(response.body, secret, &computed)) {
        burner::net::SecureWipe(secret);
        burner::net::SecureWipe(received);
        if (reason != nullptr) {
            *reason = burner::net::ErrorCode::SigCompute;
        }
        return false;
    }

    std::string lhs = ToLowerCopy(received);
    std::string rhs = ToLowerCopy(computed);
    const bool ok = ConstantTimeEqual(lhs, rhs);
    burner::net::SecureWipe(secret);
    burner::net::SecureWipe(received);
    burner::net::SecureWipe(computed);
    burner::net::SecureWipe(lhs);
    burner::net::SecureWipe(rhs);
    if (!ok && reason != nullptr) {
        *reason = burner::net::ErrorCode::SigMismatch;
    }
    return ok;
#else
    burner::net::SecureWipe(secret);
    burner::net::SecureWipe(received);
    if (reason != nullptr) {
        *reason = burner::net::ErrorCode::SigCompute;
    }
    return false;
#endif
}

} // namespace

int RunCustomHmacVerifier() {
    using namespace burner::net;

    constexpr std::string_view kEndpoint = "https://example.com/license";

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithResponseVerifier(&VerifyHmacHeader)
        .Build();

    if (!build_result.Ok()) {
        std::cerr << "Failed to build HMAC example client: "
                  << ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout << "This example keeps HMAC verification in application code, not BurnerNet core.\n";
    std::cout << "Swap the placeholder secret, endpoint, and expected header contract for your app.\n";

#ifndef _WIN32
    std::cout << "This sample uses Windows BCrypt for HMAC-SHA256 and is stubbed on non-Windows builds.\n";
    return 0;
#endif

    if (kEndpoint.find("example.com") != std::string_view::npos) {
        std::cout << "Request skipped. Replace the placeholder endpoint to exercise the custom verifier.\n";
        return 0;
    }

    const auto response = build_result.client->Get(std::string(kEndpoint)).Send();
    if (!response.TransportOk()) {
        std::cerr << "Transport failed: "
                  << ErrorCodeToString(response.transport_error) << '\n';
        return 2;
    }

    if (!response.verified) {
        std::cerr << "Custom HMAC verification failed: "
                  << ErrorCodeToString(response.verification_error) << '\n';
        return 3;
    }

    std::cout << "Custom verifier accepted the response.\n";
    return 0;
}
