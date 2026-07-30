#include "burner/net/bootstrap.h"
#include "burner/net/detail/dark_hashing.h"
#include "burner/net/detail/kernel_resolver.h"
#include "burner/net/obfuscation.h"
#include "burner/net/detail/pointer_mangling.h"
#include "curl/curl_session.h"
#include "internal/openssl_sync.h"
#include "internal/runtime_module_registry.h"

#ifdef _WIN32
#if !BURNERNET_HARDEN_IMPORTS
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwctype>
#include <memory>
#include <mutex>
#include <new>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace burner::net {

namespace {

std::mutex g_loader_mutex;
std::vector<detail::RuntimeModuleLease> g_loaded_modules;
bool g_bootstrap_in_progress = false;
std::atomic<bool> g_global_allocator_hooks_enabled{false};

using GetModuleHandleExWFn = decltype(&GetModuleHandleExW);
using LoadLibraryExWFn = decltype(&LoadLibraryExW);

constexpr std::uint32_t kKernel32Hash = ::burner::net::detail::fnv1a_ci("kernel32.dll");
constexpr std::uint32_t kKernelBaseHash = ::burner::net::detail::fnv1a_ci("kernelbase.dll");
constexpr std::uint32_t kNtDllHash = ::burner::net::detail::fnv1a_ci("ntdll.dll");
constexpr std::uint32_t kGetModuleHandleExWHash =
    ::burner::net::detail::fnv1a("GetModuleHandleExW");
constexpr std::uint32_t kLoadLibraryExWHash = ::burner::net::detail::fnv1a("LoadLibraryExW");

#if BURNERNET_MAXIMUM_GHOST
enum class MaximumGhostState : std::uint8_t {
    Uninitialized,
    Installing,
    Active,
    Partial,
    Unavailable
};

MaximumGhostState g_maximum_ghost_state = MaximumGhostState::Uninitialized;
HMODULE g_maximum_ghost_owner_module = nullptr;
#endif

#if BURNERNET_HARDEN_IMPORTS
constexpr std::uint32_t kLibCurlBootstrapHash  = ::burner::net::detail::fnv1a_ci("libcurl.dll");
constexpr std::uint32_t kLibCurlDBootstrapHash = ::burner::net::detail::fnv1a_ci("libcurl-d.dll");
#endif

template <typename TFn>
TFn ResolveSystemPrimitive(std::uint32_t export_hash) noexcept {
    // Bootstrap is the DLL-search-path boundary for BurnerNet's dynamic runtime mode.
    // We intentionally use KernelResolver here because these
    // specific loader APIs must come from the real kernel32/kernelbase images, not
    // from whatever the host process may have hooked in its IAT or loader façade.
    //
    // This also handles the modern Windows split where loader exports are frequently
    // forwarded between kernel32.dll, kernelbase.dll, and occasionally ntdll.dll.
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

#if BURNERNET_MAXIMUM_GHOST
HMODULE AcquireMaximumGhostOwnerModule() noexcept {
    if (g_maximum_ghost_owner_module != nullptr) {
        return g_maximum_ghost_owner_module;
    }

    const GetModuleHandleExWFn get_module_handle_ex_w =
        ResolveSystemPrimitive<GetModuleHandleExWFn>(kGetModuleHandleExWHash);
    if (get_module_handle_ex_w == nullptr) {
        return nullptr;
    }

    HMODULE owner_module = nullptr;
    if (!get_module_handle_ex_w(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(&AcquireMaximumGhostOwnerModule),
            &owner_module) ||
        owner_module == nullptr) {
        return nullptr;
    }

    return owner_module;
}
#endif

std::wstring ToLowerWide(const std::wstring& value) {
    std::wstring out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return out;
}

bool PathsEqualCaseInsensitive(const std::filesystem::path& a, const std::filesystem::path& b) {
    return ToLowerWide(a.wstring()) == ToLowerWide(b.wstring());
}

bool IsValidDependencyName(const std::wstring& dll_name) {
    if (dll_name.empty()) {
        return false;
    }
    const std::filesystem::path path(dll_name);
    return path == path.filename() &&
        path.has_extension() &&
        ToLowerWide(path.extension().wstring()) == L".dll";
}

class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
        : m_handle(handle) {}
    ~ScopedHandle() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
        }
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& other) noexcept
        : m_handle(std::exchange(other.m_handle, INVALID_HANDLE_VALUE)) {}
    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            if (m_handle != INVALID_HANDLE_VALUE) {
                ::CloseHandle(m_handle);
            }
            m_handle = std::exchange(other.m_handle, INVALID_HANDLE_VALUE);
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool valid() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }

private:
    HANDLE m_handle;
};

class ScopedModule final {
public:
    explicit ScopedModule(HMODULE module = nullptr) noexcept
        : m_module(module) {}
    ~ScopedModule() {
        if (m_module != nullptr) {
            ::FreeLibrary(m_module);
        }
    }
    ScopedModule(const ScopedModule&) = delete;
    ScopedModule& operator=(const ScopedModule&) = delete;
    [[nodiscard]] HMODULE get() const noexcept { return m_module; }
    [[nodiscard]] bool valid() const noexcept { return m_module != nullptr; }
    [[nodiscard]] HMODULE release() noexcept {
        HMODULE module = m_module;
        m_module = nullptr;
        return module;
    }

private:
    HMODULE m_module;
};

bool IsReparsePoint(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO tag_info{};
    return !::GetFileInformationByHandleEx(
               handle,
               FileAttributeTagInfo,
               &tag_info,
               sizeof(tag_info)) ||
        (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool SameFileIdentity(HANDLE lhs, HANDLE rhs) {
    BY_HANDLE_FILE_INFORMATION lhs_info{};
    BY_HANDLE_FILE_INFORMATION rhs_info{};
    if (!::GetFileInformationByHandle(lhs, &lhs_info) ||
        !::GetFileInformationByHandle(rhs, &rhs_info)) {
        return false;
    }
    return lhs_info.dwVolumeSerialNumber == rhs_info.dwVolumeSerialNumber &&
        lhs_info.nFileIndexHigh == rhs_info.nFileIndexHigh &&
        lhs_info.nFileIndexLow == rhs_info.nFileIndexLow;
}

detail::RuntimeModuleLease MakeModuleLease(ScopedModule& module, const std::wstring& basename) {
    auto* runtime_module = new detail::RuntimeModule{nullptr, basename};
    detail::RuntimeModuleLease lease(
        runtime_module,
        [](const detail::RuntimeModule* runtime_module) {
            if (runtime_module != nullptr) {
                if (runtime_module->handle != nullptr) {
                    ::FreeLibrary(static_cast<HMODULE>(runtime_module->handle));
                }
                delete runtime_module;
            }
        });
    runtime_module->handle = module.release();
    return lease;
}

void ReleaseModulesReverse(std::vector<detail::RuntimeModuleLease>& modules) noexcept {
    while (!modules.empty()) {
        modules.pop_back();
    }
}

struct PendingBootstrapResources final {
    std::vector<detail::RuntimeModuleLease> modules;

    PendingBootstrapResources() = default;
    ~PendingBootstrapResources() {
        Reset();
    }

    PendingBootstrapResources(const PendingBootstrapResources&) = delete;
    PendingBootstrapResources& operator=(const PendingBootstrapResources&) = delete;

    void Reset() noexcept {
        ReleaseModulesReverse(modules);
    }
};

struct LockedDependency final {
    std::wstring basename;
    std::filesystem::path full_path;
    ScopedHandle file;
};

struct BootstrapTransactionGuard final {
    bool active = true;

    ~BootstrapTransactionGuard() {
        if (active) {
            std::lock_guard<std::mutex> lock(g_loader_mutex);
            g_bootstrap_in_progress = false;
        }
    }
};

bool DependencyNameMatches(std::wstring_view lhs, std::wstring_view rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (towlower(lhs[i]) != towlower(rhs[i])) {
            return false;
        }
    }
    return true;
}

bool IsListedDependency(
    const std::vector<std::wstring>& dependency_dlls,
    std::wstring_view basename) {
    return std::any_of(
        dependency_dlls.begin(),
        dependency_dlls.end(),
        [&](const std::wstring& candidate) {
            return DependencyNameMatches(candidate, basename);
        });
}

#if BURNERNET_MAXIMUM_GHOST
void PublishMaximumGhostResult(
    GlobalAllocatorHookInstallResult result,
    HMODULE owner_candidate) noexcept {
    std::lock_guard<std::mutex> lock(g_loader_mutex);
    if (result == GlobalAllocatorHookInstallResult::Active) {
        g_maximum_ghost_state = MaximumGhostState::Active;
        g_global_allocator_hooks_enabled.store(true, std::memory_order_release);
    } else if (result == GlobalAllocatorHookInstallResult::Partial) {
        g_maximum_ghost_state = MaximumGhostState::Partial;
        g_global_allocator_hooks_enabled.store(false, std::memory_order_release);
    } else {
        g_maximum_ghost_state = MaximumGhostState::Unavailable;
        g_global_allocator_hooks_enabled.store(false, std::memory_order_release);
    }

    if (result != GlobalAllocatorHookInstallResult::Unavailable &&
        g_maximum_ghost_owner_module == nullptr) {
        // Installed callbacks can execute until process exit. Keep their owner
        // resident even when only one backend accepted the callbacks.
        g_maximum_ghost_owner_module = owner_candidate;
        owner_candidate = nullptr;
    }
    if (owner_candidate != nullptr &&
        owner_candidate != g_maximum_ghost_owner_module) {
        ::FreeLibrary(owner_candidate);
    }
}
#endif

} // namespace

namespace detail {

RuntimeModuleLease AcquireRuntimeModule(std::string_view basename) noexcept {
    std::lock_guard<std::mutex> lock(g_loader_mutex);
    for (const auto& module : g_loaded_modules) {
        if (module == nullptr || module->basename.size() != basename.size()) {
            continue;
        }
        bool equal = true;
        for (std::size_t i = 0; i < basename.size(); ++i) {
            const unsigned char narrow = static_cast<unsigned char>(basename[i]);
            if (narrow > 0x7f ||
                towlower(module->basename[i]) !=
                    static_cast<wchar_t>(std::tolower(narrow))) {
                equal = false;
                break;
            }
        }
        if (equal) {
            return module;
        }
    }
    return {};
}

ErrorCode MaximumGhostRuntimeError() noexcept {
    return ErrorCode::None;
}

} // namespace detail

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config) {
    ::burner::net::detail::InitializeEncodedPointerKey(
        reinterpret_cast<std::uintptr_t>(&config));

    try {
#if BURNERNET_MAXIMUM_GHOST
    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        if (g_maximum_ghost_state == MaximumGhostState::Active ||
            g_maximum_ghost_state == MaximumGhostState::Partial ||
            g_maximum_ghost_state == MaximumGhostState::Unavailable) {
            if (config.link_mode != LinkMode::Static && g_loaded_modules.empty()) {
                // Hook outcome is process-global, but dynamic runtime loading
                // may still be needed after an earlier linked-mode attempt.
            } else {
                return {true, ErrorCode::BootstrapSkip};
            }
        }
        if (g_maximum_ghost_state == MaximumGhostState::Installing) {
            return {false, ErrorCode::BootstrapBusy};
        }
    }

    if (config.link_mode == LinkMode::Static) {
#if BURNERNET_HARDEN_IMPORTS
        return {false, ErrorCode::BootstrapConfig};
#else
        {
            std::lock_guard<std::mutex> lock(g_loader_mutex);
            if (g_bootstrap_in_progress) {
                return {false, ErrorCode::BootstrapBusy};
            }
            g_bootstrap_in_progress = true;
            g_maximum_ghost_state = MaximumGhostState::Installing;
        }
        BootstrapTransactionGuard transaction_guard;

        HMODULE owner_candidate = AcquireMaximumGhostOwnerModule();
        GlobalAllocatorHookInstallResult hook_result =
            GlobalAllocatorHookInstallResult::Unavailable;
        if (owner_candidate != nullptr) {
            hook_result = InstallLinkedGlobalAllocatorHooks();
        }
        PublishMaximumGhostResult(hook_result, owner_candidate);

        {
            std::lock_guard<std::mutex> lock(g_loader_mutex);
            g_bootstrap_in_progress = false;
            transaction_guard.active = false;
        }
        return {true, ErrorCode::BootstrapSkip};
#endif
    }
    if (!config.preload_dependencies) {
        return {false, ErrorCode::BootstrapConfig};
    }
#else
    if (config.link_mode == LinkMode::Static || !config.preload_dependencies) {
        return {true, ErrorCode::BootstrapSkip};
    }
#endif

    if (config.dependency_directory.empty()) {
        return {false, ErrorCode::BootstrapConfig};
    }
    if (config.dependency_dlls.empty()) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }
    for (std::size_t i = 0; i < config.dependency_dlls.size(); ++i) {
        const auto& dll_name = config.dependency_dlls[i];
        if (!IsValidDependencyName(dll_name)) {
            return {false, ErrorCode::InvalidBootstrapDependency};
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (DependencyNameMatches(dll_name, config.dependency_dlls[j])) {
                return {false, ErrorCode::InvalidBootstrapDependency};
            }
        }
    }
#if BURNERNET_HARDEN_IMPORTS
    if (!config.integrity_provider) {
        return {false, ErrorCode::BootstrapIntegrityCfg};
    }
#endif

    ScopedHandle configured_directory(::CreateFileW(
        config.dependency_directory.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!configured_directory.valid() || IsReparsePoint(configured_directory.get())) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }

    std::error_code path_error;
    const std::filesystem::path canonical_directory =
        std::filesystem::canonical(config.dependency_directory, path_error);
    if (path_error || canonical_directory.empty()) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }

    ScopedHandle directory_handle(::CreateFileW(
        canonical_directory.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!directory_handle.valid() ||
        IsReparsePoint(directory_handle.get()) ||
        !SameFileIdentity(configured_directory.get(), directory_handle.get())) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }

    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        if (!g_loaded_modules.empty()) {
            return {true, ErrorCode::BootstrapSkip};
        }
        if (g_bootstrap_in_progress) {
            return {false, ErrorCode::BootstrapBusy};
        }
        g_bootstrap_in_progress = true;
    }

    BootstrapTransactionGuard transaction_guard;

    if (config.dependency_directory_guard) {
        try {
            if (!config.dependency_directory_guard(canonical_directory)) {
                return {false, ErrorCode::BootstrapDirectoryRejected};
            }
        } catch (...) {
            return {false, ErrorCode::CallbackFailed};
        }
    }

    ScopedHandle revalidated_directory(::CreateFileW(
        canonical_directory.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr));
    if (!revalidated_directory.valid() ||
        IsReparsePoint(revalidated_directory.get()) ||
        !SameFileIdentity(directory_handle.get(), revalidated_directory.get())) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }

    PendingBootstrapResources pending_resources;
    std::vector<LockedDependency> locked_dependencies;
    locked_dependencies.reserve(config.dependency_dlls.size());

#if BURNERNET_HARDEN_IMPORTS
    std::error_code enumeration_error;
    for (std::filesystem::directory_iterator it(canonical_directory, enumeration_error), end;
         !enumeration_error && it != end;
         it.increment(enumeration_error)) {
        const std::filesystem::path entry_path = it->path();
        if (ToLowerWide(entry_path.extension().wstring()) == L".dll" &&
            !IsListedDependency(config.dependency_dlls, entry_path.filename().wstring())) {
            return {false, ErrorCode::InvalidBootstrapDependency};
        }
    }
    if (enumeration_error) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }
#endif

    // Lock and validate every packaged DLL before the first LoadLibrary call.
    // This prevents one dependency from executing while a later dependency is
    // still unverified or replaceable.
    for (const auto& dll_name : config.dependency_dlls) {
        const std::filesystem::path full_path = canonical_directory / dll_name;
        ScopedHandle locked_file(::CreateFileW(
            full_path.c_str(),
            GENERIC_READ | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr));
        if (!locked_file.valid() || IsReparsePoint(locked_file.get())) {
            return {false, ErrorCode::InvalidBootstrapDependency};
        }
        locked_dependencies.push_back(
            LockedDependency{dll_name, full_path, std::move(locked_file)});
    }

    if (config.integrity_provider) {
        for (const auto& dependency : locked_dependencies) {
            bool ok = false;
            try {
                ok = config.integrity_provider(
                    dependency.full_path,
                    dependency.basename);
            } catch (...) {
                return {false, ErrorCode::CallbackFailed};
            }
            if (!ok) {
                return {false, ErrorCode::BootstrapIntegrityMismatch};
            }
        }
    }

    const LoadLibraryExWFn load_library_ex_w =
        ResolveSystemPrimitive<LoadLibraryExWFn>(kLoadLibraryExWHash);
    if (load_library_ex_w == nullptr) {
        return {false, ErrorCode::BootstrapLoad};
    }

    for (const auto& dependency : locked_dependencies) {
        ScopedModule module(load_library_ex_w(
            dependency.full_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32));
        if (!module.valid()) {
            return {false, ErrorCode::BootstrapLoad};
        }

        wchar_t loaded_path[MAX_PATH] = {};
        const DWORD n = ::GetModuleFileNameW(module.get(), loaded_path, MAX_PATH);
        ScopedHandle loaded_file(
            (n > 0 && n < MAX_PATH)
                ? ::CreateFileW(
                      loaded_path,
                      FILE_READ_ATTRIBUTES,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                      nullptr,
                      OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL,
                      nullptr)
                : INVALID_HANDLE_VALUE);
        if (n == 0 || n == MAX_PATH || !loaded_file.valid() ||
            !PathsEqualCaseInsensitive(
                std::filesystem::path(loaded_path),
                dependency.full_path) ||
            !SameFileIdentity(dependency.file.get(), loaded_file.get())) {
            return {false, ErrorCode::BootstrapModulePath};
        }

        pending_resources.modules.push_back(
            MakeModuleLease(module, dependency.basename));
    }

    // Process-global hooks are optional. Existing host initialization can make
    // them unavailable; transport remains usable and reports hooks as disabled.
#if BURNERNET_MAXIMUM_GHOST
    bool should_attempt_hooks = false;
    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        if (g_maximum_ghost_state == MaximumGhostState::Uninitialized) {
            g_maximum_ghost_state = MaximumGhostState::Installing;
            should_attempt_hooks = true;
        }
    }

    if (should_attempt_hooks) {
        HMODULE owner_candidate = AcquireMaximumGhostOwnerModule();
        GlobalAllocatorHookInstallResult hook_result =
            GlobalAllocatorHookInstallResult::Unavailable;
        if (owner_candidate != nullptr) {
#if BURNERNET_HARDEN_IMPORTS
            for (const auto& runtime_module : pending_resources.modules) {
                const std::uint32_t basename_hash =
                    ::burner::net::detail::fnv1a_ascii_wide_ci(
                        runtime_module->basename.c_str(),
                        runtime_module->basename.size());
                if (basename_hash == kLibCurlBootstrapHash ||
                    basename_hash == kLibCurlDBootstrapHash) {
                    CurlApi curl_api{};
                    curl_api.global_init_mem =
                        reinterpret_cast<CurlGlobalInitMemFn>(
                            ::burner::net::detail::KernelResolver::ResolveInternalExport(
                                runtime_module->handle,
                                ::burner::net::detail::kCurlGlobalInitMemHash));
                    curl_api.global_sslset =
                        reinterpret_cast<CurlGlobalSslSetFn>(
                            ::burner::net::detail::KernelResolver::ResolveInternalExport(
                                runtime_module->handle,
                                ::burner::net::detail::kCurlGlobalSslSetHash));
                    hook_result = InstallGlobalAllocatorHooks(curl_api);
                    break;
                }
            }
#else
            hook_result = InstallLinkedGlobalAllocatorHooks();
#endif
        }
        PublishMaximumGhostResult(hook_result, owner_candidate);
    }
#endif

    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        g_loaded_modules.swap(pending_resources.modules);
#if !BURNERNET_MAXIMUM_GHOST
        g_global_allocator_hooks_enabled.store(false, std::memory_order_release);
#endif
        g_bootstrap_in_progress = false;
        transaction_guard.active = false;
    }
    return {true, ErrorCode::BootstrapLoaded};
    } catch (const std::bad_alloc&) {
        return {false, ErrorCode::OutOfMemory};
    } catch (...) {
        return {false, ErrorCode::CallbackFailed};
    }
}

bool GlobalAllocatorHooksEnabled() noexcept {
    return g_global_allocator_hooks_enabled.load(std::memory_order_acquire);
}

void ShutdownNetworkingRuntime() noexcept {
    std::vector<detail::RuntimeModuleLease> modules;
    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        if (g_bootstrap_in_progress) {
            return;
        }
#if BURNERNET_MAXIMUM_GHOST
        if (g_maximum_ghost_state == MaximumGhostState::Active ||
            g_maximum_ghost_state == MaximumGhostState::Partial) {
            // Allocator callbacks and their owning module are process-lifetime.
            // Unloading runtime modules would make later backend reuse ambiguous.
            return;
        }
#endif
        modules.swap(g_loaded_modules);
        g_global_allocator_hooks_enabled.store(false, std::memory_order_release);
    }

    // Never execute DLL detach code while registry mutex is held. A module's
    // loader callback may otherwise re-enter runtime lookup and deadlock.
    ReleaseModulesReverse(modules);
}

} // namespace burner::net

#else

namespace burner::net {

namespace detail {

ErrorCode MaximumGhostRuntimeError() noexcept {
    return ErrorCode::None;
}

} // namespace detail

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig&) {
    ::burner::net::detail::InitializeEncodedPointerKey();
    return {true, ErrorCode::BootstrapWinOnly};
}

void ShutdownNetworkingRuntime() noexcept {}
bool GlobalAllocatorHooksEnabled() noexcept { return false; }

} // namespace burner::net

#endif
