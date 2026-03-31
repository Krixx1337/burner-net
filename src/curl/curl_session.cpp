#include "curl_session.h"

#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/obfuscation.h"

#include <cstdarg>

#ifdef _WIN32
#include <windows.h>

#if defined(_MSC_VER)
#if !BURNERNET_HARDEN_IMPORTS
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

#endif

namespace burner::net {
namespace {

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

#if BURNERNET_HARDEN_IMPORTS && defined(_WIN32)
using GetModuleHandleAFn = decltype(&GetModuleHandleA);
using GetProcAddressFn = decltype(&GetProcAddress);

constexpr std::uint32_t kKernel32Hash = ::burner::net::detail::fnv1a_ci("kernel32.dll");
constexpr std::uint32_t kKernelBaseHash = ::burner::net::detail::fnv1a_ci("kernelbase.dll");
constexpr std::uint32_t kNtDllHash = ::burner::net::detail::fnv1a_ci("ntdll.dll");
constexpr std::uint32_t kGetModuleHandleAHash = ::burner::net::detail::fnv1a("GetModuleHandleA");
constexpr std::uint32_t kGetProcAddressHash = ::burner::net::detail::fnv1a("GetProcAddress");

template <typename TFn>
TFn ResolveSystemPrimitive(std::uint32_t export_hash) noexcept {
    // curl_session builds the resolver for the rest of the library, so it must not
    // depend on lazy-importer or ambient IAT state for GetModuleHandleA/GetProcAddress.
    // Anchor those primitives in the real system images first, then use them to reach
    // the non-system libcurl module.
    constexpr std::uint32_t kModuleHashes[] = {kKernelBaseHash, kKernel32Hash, kNtDllHash};
    for (const std::uint32_t module_hash : kModuleHashes) {
        if (void* const module = ::burner::net::detail::KernelResolver::GetSystemModule(module_hash)) {
            if (void* const resolved =
                    ::burner::net::detail::KernelResolver::ResolveInternalExport(module, export_hash)) {
                return reinterpret_cast<TFn>(resolved);
            }
        }
    }

    return nullptr;
}

HMODULE ResolveConfiguredCurlModule(const ClientConfig& config) noexcept {
    static const GetModuleHandleAFn get_module_handle =
        ResolveSystemPrimitive<GetModuleHandleAFn>(kGetModuleHandleAHash);
    if (get_module_handle == nullptr) {
        return nullptr;
    }

    if (!config.curl_module_name.empty()) {
        return get_module_handle(config.curl_module_name.c_str());
    }

    const std::string default_name =
#if defined(_DEBUG)
        BURNER_OBF_LITERAL("libcurl-d.dll");
#else
        BURNER_OBF_LITERAL("libcurl.dll");
#endif
    return get_module_handle(default_name.c_str());
}

template <typename TFn>
TFn ResolveCurlExport(HMODULE module, const char* export_name) noexcept {
    if (module == nullptr) {
        return nullptr;
    }

    static const GetProcAddressFn get_proc_address =
        ResolveSystemPrimitive<GetProcAddressFn>(kGetProcAddressHash);
    if (get_proc_address == nullptr) {
        return nullptr;
    }

    // Resolve libcurl exports through the real GetProcAddress provider recovered from
    // kernel32/kernelbase rather than the host process import path.
    return reinterpret_cast<TFn>(get_proc_address(module, export_name));
}

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

CurlApi MakeResolvedCurlApi(const ClientConfig& config) {
    CurlApi api{};
#ifdef _WIN32
    const HMODULE curl_module = ResolveConfiguredCurlModule(config);
    if (curl_module == nullptr) {
        return api;
    }

    api.easy_init = ResolveCurlExport<CurlEasyInitFn>(curl_module, "curl_easy_init");
    api.easy_cleanup = ResolveCurlExport<CurlEasyCleanupFn>(curl_module, "curl_easy_cleanup");
    api.easy_reset = ResolveCurlExport<CurlEasyResetFn>(curl_module, "curl_easy_reset");
    api.easy_setopt = ResolveCurlExport<CurlEasySetoptFn>(curl_module, "curl_easy_setopt");
    api.easy_perform = ResolveCurlExport<CurlEasyPerformFn>(curl_module, "curl_easy_perform");
    api.easy_getinfo = ResolveCurlExport<CurlEasyGetinfoFn>(curl_module, "curl_easy_getinfo");
    api.slist_append = ResolveCurlExport<CurlSlistAppendFn>(curl_module, "curl_slist_append");
    api.slist_free_all = ResolveCurlExport<CurlSlistFreeAllFn>(curl_module, "curl_slist_free_all");
    api.easy_strerror = ResolveCurlExport<CurlEasyStrerrorFn>(curl_module, "curl_easy_strerror");
#endif
    return api;
}
#endif

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
#ifdef _WIN32
    curl_api = MakeResolvedCurlApi(config);
    if (!IsCurlApiComplete(curl_api)) {
        *init_error = ErrorCode::CurlApiIncomplete;
        return nullptr;
    }
#else
    (void)config;
    curl_api = MakeWrappedCurlApi();
#endif
#else
    (void)config;
    curl_api = MakeWrappedCurlApi();
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
