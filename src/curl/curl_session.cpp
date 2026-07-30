#include "curl_session.h"

#include "burner/net/bootstrap.h"
#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/detail/wiping_alloc_engine.h"
#include "burner/net/obfuscation.h"
#include "internal/openssl_sync.h"

#include <mutex>
#include <new>

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

CURLcode DefaultCurlEasyPerform(CURL* easy) {
    return curl_easy_perform(easy);
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
    api.easy_setopt = reinterpret_cast<CurlEasySetoptFn>(&curl_easy_setopt);
    api.easy_perform = &DefaultCurlEasyPerform;
    api.easy_getinfo = reinterpret_cast<CurlEasyGetinfoFn>(&curl_easy_getinfo);
    api.slist_append = &DefaultCurlSlistAppend;
    api.slist_free_all = &DefaultCurlSlistFreeAll;
    api.easy_strerror = &DefaultCurlEasyStrerror;
    api.global_init_mem = reinterpret_cast<CurlGlobalInitMemFn>(&curl_global_init_mem);
    api.global_sslset = reinterpret_cast<CurlGlobalSslSetFn>(&curl_global_sslset);
    return api;
}

#if BURNERNET_HARDEN_IMPORTS && defined(_WIN32)
constexpr std::uint32_t kCurlEasyInitHash = ::burner::net::detail::fnv1a("curl_easy_init");
constexpr std::uint32_t kCurlEasyCleanupHash = ::burner::net::detail::fnv1a("curl_easy_cleanup");
constexpr std::uint32_t kCurlEasyResetHash = ::burner::net::detail::fnv1a("curl_easy_reset");
constexpr std::uint32_t kCurlEasySetoptHash = ::burner::net::detail::fnv1a("curl_easy_setopt");
constexpr std::uint32_t kCurlEasyPerformHash = ::burner::net::detail::fnv1a("curl_easy_perform");
constexpr std::uint32_t kCurlEasyGetinfoHash = ::burner::net::detail::fnv1a("curl_easy_getinfo");
constexpr std::uint32_t kCurlSlistAppendHash = ::burner::net::detail::fnv1a("curl_slist_append");
constexpr std::uint32_t kCurlSlistFreeAllHash = ::burner::net::detail::fnv1a("curl_slist_free_all");
constexpr std::uint32_t kCurlEasyStrerrorHash = ::burner::net::detail::fnv1a("curl_easy_strerror");
constexpr std::uint32_t kCurlGlobalInitMemHash = ::burner::net::detail::kCurlGlobalInitMemHash;
constexpr std::uint32_t kCurlGlobalSslSetHash = ::burner::net::detail::kCurlGlobalSslSetHash;

detail::RuntimeModuleLease ResolveConfiguredCurlModule(const ClientConfig& config) noexcept {
    if (!config.curl_module_name.empty()) {
        return detail::AcquireRuntimeModule(config.curl_module_name);
    }

#if defined(_DEBUG)
    return detail::AcquireRuntimeModule("libcurl-d.dll");
#else
    return detail::AcquireRuntimeModule("libcurl.dll");
#endif
}

template <typename TFn>
TFn ResolveCurlExportByHash(HMODULE module, std::uint32_t export_hash) noexcept {
    if (module == nullptr) {
        return nullptr;
    }

    return reinterpret_cast<TFn>(
        ::burner::net::detail::KernelResolver::ResolveInternalExport(module, export_hash));
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

CurlApi MakeResolvedCurlApi(const ClientConfig& config, detail::RuntimeModuleLease* module_lease) {
    CurlApi api{};
#ifdef _WIN32
    detail::RuntimeModuleLease lease = ResolveConfiguredCurlModule(config);
    const HMODULE curl_module = lease
        ? static_cast<HMODULE>(lease->handle)
        : nullptr;
    if (curl_module == nullptr) {
        return api;
    }
    if (module_lease != nullptr) {
        *module_lease = std::move(lease);
    }

    api.easy_init = ResolveCurlExportByHash<CurlEasyInitFn>(curl_module, kCurlEasyInitHash);
    api.easy_cleanup = ResolveCurlExportByHash<CurlEasyCleanupFn>(curl_module, kCurlEasyCleanupHash);
    api.easy_reset = ResolveCurlExportByHash<CurlEasyResetFn>(curl_module, kCurlEasyResetHash);
    api.easy_setopt = ResolveCurlExportByHash<CurlEasySetoptFn>(curl_module, kCurlEasySetoptHash);
    api.easy_perform = ResolveCurlExportByHash<CurlEasyPerformFn>(curl_module, kCurlEasyPerformHash);
    api.easy_getinfo = ResolveCurlExportByHash<CurlEasyGetinfoFn>(curl_module, kCurlEasyGetinfoHash);
    api.slist_append = ResolveCurlExportByHash<CurlSlistAppendFn>(curl_module, kCurlSlistAppendHash);
    api.slist_free_all = ResolveCurlExportByHash<CurlSlistFreeAllFn>(curl_module, kCurlSlistFreeAllHash);
    api.easy_strerror = ResolveCurlExportByHash<CurlEasyStrerrorFn>(curl_module, kCurlEasyStrerrorHash);
    api.global_init_mem = ResolveCurlExportByHash<CurlGlobalInitMemFn>(curl_module, kCurlGlobalInitMemHash);
    api.global_sslset = ResolveCurlExportByHash<CurlGlobalSslSetFn>(curl_module, kCurlGlobalSslSetHash);
#endif
    return api;
}
#endif

} // namespace

bool EnsureCurlGlobalZapped(const CurlApi& api) noexcept {
    static std::once_flag s_curl_zapped;
    static bool s_result = false;
    std::call_once(s_curl_zapped, [&api]() {
        if (!api.global_init_mem) {
            return;
        }
        const CURLcode result = api.global_init_mem(
            CURL_GLOBAL_ALL,
            reinterpret_cast<CurlMallocCallback>(&::burner::net::detail::alloc::dark_malloc),
            reinterpret_cast<CurlFreeCallback>(&::burner::net::detail::alloc::dark_free),
            reinterpret_cast<CurlReallocCallback>(&::burner::net::detail::alloc::dark_realloc),
            reinterpret_cast<CurlStrdupCallback>(&::burner::net::detail::alloc::dark_strdup),
            reinterpret_cast<CurlCallocCallback>(&::burner::net::detail::alloc::dark_calloc));
        s_result = result == CURLE_OK;
    });
    return s_result;
}

bool InstallLinkedGlobalAllocatorHooks() noexcept {
#if BURNERNET_HARDEN_IMPORTS
    return false;
#else
    const CurlApi curl_api = MakeWrappedCurlApi();
    return InstallGlobalAllocatorHooks(curl_api);
#endif
}

bool InstallGlobalAllocatorHooks(const CurlApi& api) noexcept {
    if (!api.global_sslset ||
        api.global_sslset(CURLSSLBACKEND_OPENSSL, nullptr, nullptr) != CURLSSLSET_OK) {
        return false;
    }
    return TryApplyOpenSSLHooks() && EnsureCurlGlobalZapped(api);
}

CurlSession::CurlSession(CurlApi api, detail::RuntimeModuleLease module_lease)
    : m_api(std::move(api)),
      m_module_lease(std::move(module_lease)),
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

#if BURNERNET_MAXIMUM_GHOST
    // Process-global allocators must be installed during explicit bootstrap,
    // before any client can create backend state.
    const ErrorCode runtime_error = detail::MaximumGhostRuntimeError();
    if (runtime_error != ErrorCode::None) {
        *init_error = runtime_error;
        return nullptr;
    }
#endif

    CurlApi curl_api{};
    detail::RuntimeModuleLease module_lease;
#if BURNERNET_HARDEN_IMPORTS
#ifdef _WIN32
    curl_api = MakeResolvedCurlApi(config, &module_lease);
    if (!IsCurlApiComplete(curl_api)) {
        *init_error = module_lease
            ? ErrorCode::CurlApiIncomplete
            : ErrorCode::NetworkingRuntimeUnavailable;
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

    auto session = std::unique_ptr<CurlSession>(
        new (std::nothrow) CurlSession(curl_api, std::move(module_lease)));
    if (!session) {
        *init_error = ErrorCode::OutOfMemory;
        return nullptr;
    }
    if (!session->IsInitialized()) {
        *init_error = ErrorCode::InitCurl;
        return nullptr;
    }

    *init_error = ErrorCode::None;
    return session;
}

} // namespace burner::net
