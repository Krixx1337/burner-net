#include "burner/net/signature_verifier.h"
#include "burner/net/obfuscation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
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
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD cb_result = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status < 0) {
        return false;
    }

    status = BCryptGetProperty(
        alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &cb_result, 0);
    if (status < 0 || object_size == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    std::vector<unsigned char> object_buffer(object_size);
    std::array<unsigned char, 32> hash_bytes{};

    const auto cleanup = [&]() {
        burner::net::SecureWipe(object_buffer);
        burner::net::SecureWipe(std::span<unsigned char>(hash_bytes.data(), hash_bytes.size()));
    };

    status = BCryptCreateHash(
        alg,
        &hash,
        object_buffer.data(),
        static_cast<ULONG>(object_buffer.size()),
        reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
        static_cast<ULONG>(secret.size()),
        0);
    if (status < 0) {
        cleanup();
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    status = BCryptHashData(hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
        static_cast<ULONG>(data.size()), 0);
    if (status < 0) {
        cleanup();
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    status = BCryptFinishHash(hash, hash_bytes.data(), static_cast<ULONG>(hash_bytes.size()), 0);
    if (status < 0) {
        cleanup();
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

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

bool HmacSha256HeaderVerifier::Verify(const HttpRequest&, const HttpResponse& response, ErrorCode* reason) {
    std::string secret;
    if (m_config.secret_provider) {
        if (!m_config.secret_provider(secret)) {
            SecureWipe(secret);
            if (reason) *reason = ErrorCode::SigProvider;
            return false;
        }
    } else {
        secret = m_config.secret;
    }

    if (secret.empty()) {
        SecureWipe(secret);
        if (reason) *reason = ErrorCode::SigEmpty;
        return false;
    }

    std::string received = Trim(GetHeaderCaseInsensitive(response.headers, m_config.signature_header));
    if (received.empty()) {
        SecureWipe(secret);
        if (reason) *reason = ErrorCode::SigHeaderMissing;
        return false;
    }

    std::string computed;
    if (!ComputeHmacSha256Hex(response.body, secret, &computed)) {
        SecureWipe(secret);
        SecureWipe(received);
        if (reason) *reason = ErrorCode::SigCompute;
        return false;
    }
    SecureWipe(secret);

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
