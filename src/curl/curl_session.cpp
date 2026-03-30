#include "curl_session.h"

#include "burner/net/obfuscation.h"
#include "../internal/import_pointer_trust.h"

#include <cstdarg>

#ifdef _WIN32
#include <windows.h>
#include "burner/net/external/lazy_importer/lazy_importer.hpp"

#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "normaliz.lib")
#endif
#endif

namespace burner::net {
namespace {

#ifdef _WIN32
void* ResolveLoadedCurlModule() noexcept {
    if (void* module = LI_MODULE("libcurl.dll").safe_cached()) {
        return module;
    }
    if (void* module = LI_MODULE("libcurl-d.dll").safe_cached()) {
        return module;
    }
    if (void* module = LI_MODULE("libcurl-x64.dll").safe_cached()) {
        return module;
    }
    return LI_MODULE("libcurl-x86.dll").safe_cached();
}
#endif

bool IsCurlApiComplete(const CurlApi& api) {
    return static_cast<bool>(api.easy_init) &&
        static_cast<bool>(api.easy_cleanup) &&
        static_cast<bool>(api.easy_reset) &&
        static_cast<bool>(api.easy_setopt) &&
        static_cast<bool>(api.easy_perform) &&
        static_cast<bool>(api.easy_getinfo) &&
        static_cast<bool>(api.slist_append) &&
        static_cast<bool>(api.slist_free_all) &&
        static_cast<bool>(api.easy_strerror);
}

CURL* DefaultCurlEasyInit() {
    return curl_easy_init();
}

void DefaultCurlEasyCleanup(CURL* easy) {
    curl_easy_cleanup(easy);
}

void DefaultCurlEasyReset(CURL* easy) {
    curl_easy_reset(easy);
}

CURLcode DefaultCurlEasySetopt(CURL* easy, CURLoption option, ...) {
    va_list args;
    va_start(args, option);
    CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;

    switch (option) {
    case CURLOPT_WRITEDATA:
    case CURLOPT_HEADERDATA:
    case CURLOPT_XFERINFODATA:
        code = curl_easy_setopt(easy, option, va_arg(args, void*));
        break;
    case CURLOPT_HTTPHEADER:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_slist*));
        break;
    case CURLOPT_SSLCERT_BLOB:
    case CURLOPT_SSLKEY_BLOB:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_blob*));
        break;
    case CURLOPT_WRITEFUNCTION:
    case CURLOPT_HEADERFUNCTION:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_write_callback));
        break;
#ifdef CURLOPT_XFERINFOFUNCTION
    case CURLOPT_XFERINFOFUNCTION:
        code = curl_easy_setopt(easy, option, va_arg(args, curl_xferinfo_callback));
        break;
#endif
    case CURLOPT_URL:
    case CURLOPT_ERRORBUFFER:
    case CURLOPT_PROXY:
    case CURLOPT_PINNEDPUBLICKEY:
    case CURLOPT_PROTOCOLS_STR:
    case CURLOPT_REDIR_PROTOCOLS_STR:
    case CURLOPT_USERAGENT:
    case CURLOPT_POSTFIELDS:
    case CURLOPT_CUSTOMREQUEST:
    case CURLOPT_KEYPASSWD:
    case CURLOPT_SSLCERTTYPE:
    case CURLOPT_SSLKEYTYPE:
    case CURLOPT_DOH_URL:
        code = curl_easy_setopt(easy, option, va_arg(args, char*));
        break;
    case CURLOPT_FOLLOWLOCATION:
    case CURLOPT_DISALLOW_USERNAME_IN_URL:
    case CURLOPT_MAXREDIRS:
    case CURLOPT_TIMEOUT:
    case CURLOPT_CONNECTTIMEOUT:
    case CURLOPT_SSL_VERIFYPEER:
    case CURLOPT_SSL_VERIFYHOST:
    case CURLOPT_SSLVERSION:
    case CURLOPT_SSL_OPTIONS:
    case CURLOPT_HTTPGET:
    case CURLOPT_POST:
    case CURLOPT_POSTFIELDSIZE:
    case CURLOPT_DOH_SSL_VERIFYPEER:
    case CURLOPT_DOH_SSL_VERIFYHOST:
    case CURLOPT_NOPROGRESS:
#ifdef CURLOPT_PROTOCOLS
    case CURLOPT_PROTOCOLS:
#endif
#ifdef CURLOPT_REDIR_PROTOCOLS
    case CURLOPT_REDIR_PROTOCOLS:
#endif
        code = curl_easy_setopt(easy, option, va_arg(args, long));
        break;
    default:
        break;
    }

    va_end(args);
    return code;
}

CURLcode DefaultCurlEasyPerform(CURL* easy) {
    return curl_easy_perform(easy);
}

CURLcode DefaultCurlEasyGetinfo(CURL* easy, CURLINFO info, ...) {
    va_list args;
    va_start(args, info);
    CURLcode code = CURLE_BAD_FUNCTION_ARGUMENT;

    switch (info) {
    case CURLINFO_RESPONSE_CODE:
        code = curl_easy_getinfo(easy, info, va_arg(args, long*));
        break;
    case CURLINFO_PRIMARY_IP:
        code = curl_easy_getinfo(easy, info, va_arg(args, char**));
        break;
    default:
        break;
    }

    va_end(args);
    return code;
}

curl_slist* DefaultCurlSlistAppend(curl_slist* list, const char* value) {
    return curl_slist_append(list, value);
}

void DefaultCurlSlistFreeAll(curl_slist* list) {
    curl_slist_free_all(list);
}

const char* DefaultCurlEasyStrerror(CURLcode code) {
    return curl_easy_strerror(code);
}

CurlApi MakeWrappedCurlApi() {
    CurlApi api{};
    api.easy_init = &DefaultCurlEasyInit;
    api.easy_cleanup = &DefaultCurlEasyCleanup;
    api.easy_reset = &DefaultCurlEasyReset;
    api.easy_setopt = &DefaultCurlEasySetopt;
    api.easy_perform = &DefaultCurlEasyPerform;
    api.easy_getinfo = &DefaultCurlEasyGetinfo;
    api.slist_append = &DefaultCurlSlistAppend;
    api.slist_free_all = &DefaultCurlSlistFreeAll;
    api.easy_strerror = &DefaultCurlEasyStrerror;
    return api;
}

CurlApi MakeResolvedCurlApi() {
    CurlApi api{};
#ifdef _WIN32
    const void* curl_module = ResolveLoadedCurlModule();
    if (curl_module == nullptr) {
        return api;
    }

    api.easy_init = LI_FN(curl_easy_init).in_safe<CurlEasyInitFn>(curl_module);
    api.easy_cleanup = LI_FN(curl_easy_cleanup).in_safe<CurlEasyCleanupFn>(curl_module);
    api.easy_reset = LI_FN(curl_easy_reset).in_safe<CurlEasyResetFn>(curl_module);
    api.easy_setopt = LI_FN(curl_easy_setopt).in_safe<CurlEasySetoptFn>(curl_module);
    api.easy_perform = LI_FN(curl_easy_perform).in_safe<CurlEasyPerformFn>(curl_module);
    api.easy_getinfo = LI_FN(curl_easy_getinfo).in_safe<CurlEasyGetinfoFn>(curl_module);
    api.slist_append = LI_FN(curl_slist_append).in_safe<CurlSlistAppendFn>(curl_module);
    api.slist_free_all = LI_FN(curl_slist_free_all).in_safe<CurlSlistFreeAllFn>(curl_module);
    api.easy_strerror = LI_FN(curl_easy_strerror).in_safe<CurlEasyStrerrorFn>(curl_module);
#endif
    return api;
}

bool IsCurlApiTrusted(const CurlApi& api, const std::vector<std::wstring>& trusted_module_basenames) {
    return internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_init.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_cleanup.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_reset.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_setopt.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_perform.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_getinfo.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.slist_append.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.slist_free_all.get()), trusted_module_basenames) &&
        internal::IsFunctionPointerTrusted(reinterpret_cast<const void*>(api.easy_strerror.get()), trusted_module_basenames);
}

} // namespace

CurlSession::CurlSession(CurlApi api)
    : m_api(std::move(api)),
      m_easy(m_api.easy_init ? m_api.easy_init() : nullptr) {}

CurlSession::~CurlSession() {
    if (m_easy != nullptr) {
        m_api.easy_cleanup(m_easy);
    }
}

bool CurlSession::IsInitialized() const noexcept {
    return m_easy != nullptr;
}

CURL* CurlSession::EasyHandle() const noexcept {
    return m_easy;
}

const CurlApi& CurlSession::Api() const noexcept {
    return m_api;
}

void CurlSession::Reset() const {
    if (m_easy != nullptr) {
        m_api.easy_reset(m_easy);
    }
}

std::unique_ptr<CurlSession> CreateCurlSession(const ClientConfig& config, ErrorCode* init_error) {
    if (init_error == nullptr) {
        return nullptr;
    }

    CurlApi curl_api{};
#if BURNERNET_HARDEN_IMPORTS
    curl_api = MakeResolvedCurlApi();
    if (!IsCurlApiComplete(curl_api)) {
        *init_error = ErrorCode::CurlApiIncomplete;
        return nullptr;
    }
    if (config.verify_curl_api_pointers &&
        !IsCurlApiTrusted(curl_api, config.trusted_curl_module_basenames)) {
        config.security_policy.OnTamper();
        *init_error = ErrorCode::CurlApiUntrusted;
        return nullptr;
    }
#else
    if (config.verify_curl_api_pointers) {
        curl_api = MakeResolvedCurlApi();
        if (!IsCurlApiComplete(curl_api)) {
            *init_error = ErrorCode::CurlApiIncomplete;
            return nullptr;
        }
        if (!IsCurlApiTrusted(curl_api, config.trusted_curl_module_basenames)) {
            config.security_policy.OnTamper();
            *init_error = ErrorCode::CurlApiUntrusted;
            return nullptr;
        }
    } else {
        curl_api = MakeWrappedCurlApi();
    }
#endif

    auto session = std::unique_ptr<CurlSession>(new CurlSession(curl_api));
    if (!session->IsInitialized()) {
        *init_error = ErrorCode::InitCurl;
        return nullptr;
    }

    *init_error = ErrorCode::None;
    return session;
}

} // namespace burner::net
