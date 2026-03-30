#include "burner/net/signature_verifier.h"
#include "burner/net/obfuscation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#pragma comment(lib, "bcrypt.lib")
#include <windows.h>
#include <bcrypt.h>
#include "burner/net/external/lazy_importer/lazy_importer.hpp"
#endif

namespace burner::net {

namespace {

std::string ToLowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string Trim(std::string s) {
    auto is_ws = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };

    while (!s.empty() && is_ws(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }

    size_t i = 0;
    while (i < s.size() && is_ws(static_cast<unsigned char>(s[i]))) {
        ++i;
    }

    if (i > 0) {
        s.erase(0, i);
    }

    return s;
}

std::string GetHeaderCaseInsensitive(const HeaderMap& headers, const std::string& name) {
    const std::string key = ToLowerCopy(name);
    for (const auto& [header_name, value] : headers) {
        if (ToLowerCopy(header_name) == key) {
            return value;
        }
    }
    return {};
}

bool ConstantTimeEqual(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }

    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

#ifdef _WIN32
using BCryptOpenAlgorithmProviderFn = decltype(&BCryptOpenAlgorithmProvider);
using BCryptGetPropertyFn = decltype(&BCryptGetProperty);
using BCryptCreateHashFn = decltype(&BCryptCreateHash);
using BCryptHashDataFn = decltype(&BCryptHashData);
using BCryptFinishHashFn = decltype(&BCryptFinishHash);
using BCryptDestroyHashFn = decltype(&BCryptDestroyHash);
using BCryptCloseAlgorithmProviderFn = decltype(&BCryptCloseAlgorithmProvider);

std::string ToHexLower(const unsigned char* bytes, size_t len) {
    auto nibble_to_hex = [](unsigned char nibble) -> char {
        nibble &= 0x0F;
        return static_cast<char>(nibble < 10 ? ('0' + nibble) : ('a' + (nibble - 10)));
    };

    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = nibble_to_hex(static_cast<unsigned char>((bytes[i] >> 4) & 0x0F));
        out[i * 2 + 1] = nibble_to_hex(static_cast<unsigned char>(bytes[i] & 0x0F));
    }
    return out;
}
#endif

bool ComputeHmacSha256Hex(std::string_view data, std::string_view secret, std::string* out_hex) {
    if (out_hex == nullptr) {
        return false;
    }

#ifdef _WIN32
    const BCryptOpenAlgorithmProviderFn bcrypt_open_algorithm_provider =
        LI_FN(BCryptOpenAlgorithmProvider).in_safe<BCryptOpenAlgorithmProviderFn>(LI_MODULE("bcrypt.dll").safe_cached());
    const BCryptGetPropertyFn bcrypt_get_property =
        LI_FN(BCryptGetProperty).in_safe<BCryptGetPropertyFn>(LI_MODULE("bcrypt.dll").safe_cached());
    const BCryptCreateHashFn bcrypt_create_hash =
        LI_FN(BCryptCreateHash).in_safe<BCryptCreateHashFn>(LI_MODULE("bcrypt.dll").safe_cached());
    const BCryptHashDataFn bcrypt_hash_data =
        LI_FN(BCryptHashData).in_safe<BCryptHashDataFn>(LI_MODULE("bcrypt.dll").safe_cached());
    const BCryptFinishHashFn bcrypt_finish_hash =
        LI_FN(BCryptFinishHash).in_safe<BCryptFinishHashFn>(LI_MODULE("bcrypt.dll").safe_cached());
    const BCryptDestroyHashFn bcrypt_destroy_hash =
        LI_FN(BCryptDestroyHash).in_safe<BCryptDestroyHashFn>(LI_MODULE("bcrypt.dll").safe_cached());
    const BCryptCloseAlgorithmProviderFn bcrypt_close_algorithm_provider =
        LI_FN(BCryptCloseAlgorithmProvider).in_safe<BCryptCloseAlgorithmProviderFn>(LI_MODULE("bcrypt.dll").safe_cached());
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

    status = bcrypt_hash_data(hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
        static_cast<ULONG>(data.size()), 0);
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
#else
    (void)data;
    (void)secret;
    return false;
#endif
}

} // namespace

HmacSha256HeaderVerifier::HmacSha256HeaderVerifier(SignatureVerifierConfig config)
    : m_config(std::move(config)) {}

bool HmacSha256HeaderVerifier::Verify(const HttpRequest&, const HttpResponse& response, ErrorCode* reason) const {
    SecureString secret;
    if (m_config.secret_provider) {
        std::string provided_secret;
        if (!m_config.secret_provider(provided_secret)) {
            SecureWipe(provided_secret);
            if (reason) *reason = ErrorCode::SigProvider;
            return false;
        }
        secret = std::move(provided_secret);
        SecureWipe(provided_secret);
    } else {
        secret = m_config.secret;
    }

    if (secret.empty()) {
        if (reason) *reason = ErrorCode::SigEmpty;
        return false;
    }

    std::string received = Trim(GetHeaderCaseInsensitive(response.headers, m_config.signature_header));
    if (received.empty()) {
        if (reason) *reason = ErrorCode::SigHeaderMissing;
        return false;
    }

    std::string computed;
    if (!ComputeHmacSha256Hex(response.body, secret, &computed)) {
        SecureWipe(received);
        if (reason) *reason = ErrorCode::SigCompute;
        return false;
    }

    std::string lhs = ToLowerCopy(received);
    std::string rhs = ToLowerCopy(computed);
    const bool ok = ConstantTimeEqual(lhs, rhs);
    SecureWipe(lhs);
    SecureWipe(rhs);
    SecureWipe(computed);
    if (!ok && reason) {
        *reason = ErrorCode::SigMismatch;
    }
    SecureWipe(received);
    return ok;
}

} // namespace burner::net
