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
#include <system_error>
#include <vector>

namespace burner::net {

namespace {

std::mutex g_loader_mutex;
std::vector<detail::RuntimeModuleLease> g_loaded_modules;
DLL_DIRECTORY_COOKIE g_dependency_cookie = nullptr;
bool g_bootstrap_in_progress = false;
std::atomic<bool> g_global_allocator_hooks_enabled{false};

using AddDllDirectoryFn = decltype(&AddDllDirectory);
using LoadLibraryExWFn = decltype(&LoadLibraryExW);
using SetDefaultDllDirectoriesFn = decltype(&SetDefaultDllDirectories);
using RemoveDllDirectoryFn = decltype(&RemoveDllDirectory);

constexpr std::uint32_t kKernel32Hash = ::burner::net::detail::fnv1a_ci("kernel32.dll");
constexpr std::uint32_t kKernelBaseHash = ::burner::net::detail::fnv1a_ci("kernelbase.dll");
constexpr std::uint32_t kNtDllHash = ::burner::net::detail::fnv1a_ci("ntdll.dll");
constexpr std::uint32_t kAddDllDirectoryHash = ::burner::net::detail::fnv1a("AddDllDirectory");
constexpr std::uint32_t kLoadLibraryExWHash = ::burner::net::detail::fnv1a("LoadLibraryExW");
constexpr std::uint32_t kSetDefaultDllDirectoriesHash =
    ::burner::net::detail::fnv1a("SetDefaultDllDirectories");
constexpr std::uint32_t kRemoveDllDirectoryHash = ::burner::net::detail::fnv1a("RemoveDllDirectory");

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
    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool valid() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }

private:
    HANDLE m_handle;
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

detail::RuntimeModuleLease MakeModuleLease(HMODULE module, const std::wstring& basename) {
    return detail::RuntimeModuleLease(
        new detail::RuntimeModule{module, basename},
        [](const detail::RuntimeModule* runtime_module) {
            if (runtime_module != nullptr) {
                if (runtime_module->handle != nullptr) {
                    ::FreeLibrary(static_cast<HMODULE>(runtime_module->handle));
                }
                delete runtime_module;
            }
        });
}

void ReleaseModulesReverse(std::vector<detail::RuntimeModuleLease>& modules) noexcept {
    while (!modules.empty()) {
        modules.pop_back();
    }
}

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

} // namespace detail

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config) {
    ::burner::net::detail::InitializeEncodedPointerKey(
        reinterpret_cast<std::uintptr_t>(&config));

    try {
    if (config.link_mode == LinkMode::Static || !config.preload_dependencies) {
        g_global_allocator_hooks_enabled.store(
            config.install_global_allocator_hooks,
            std::memory_order_release);
        return {true, ErrorCode::BootstrapSkip};
    }

    if (config.dependency_directory.empty()) {
        return {false, ErrorCode::BootstrapConfig};
    }
    if (config.dependency_dlls.empty()) {
        return {false, ErrorCode::InvalidBootstrapDependency};
    }
    for (const auto& dll_name : config.dependency_dlls) {
        if (!IsValidDependencyName(dll_name)) {
            return {false, ErrorCode::InvalidBootstrapDependency};
        }
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
    if (!directory_handle.valid() || IsReparsePoint(directory_handle.get())) {
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

    struct TransactionGuard final {
        bool active = true;
        ~TransactionGuard() {
            if (active) {
                std::lock_guard<std::mutex> lock(g_loader_mutex);
                g_bootstrap_in_progress = false;
            }
        }
    } transaction_guard;

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

    std::vector<detail::RuntimeModuleLease> pending_modules;
    DLL_DIRECTORY_COOKIE pending_cookie = nullptr;
    auto rollback = [&]() noexcept {
        ReleaseModulesReverse(pending_modules);
        if (pending_cookie != nullptr) {
            const RemoveDllDirectoryFn remove_directory =
                ResolveSystemPrimitive<RemoveDllDirectoryFn>(kRemoveDllDirectoryHash);
            if (remove_directory != nullptr) {
                (void)remove_directory(pending_cookie);
            }
            pending_cookie = nullptr;
        }
    };

    if (g_dependency_cookie == nullptr) {
        // Keep loader-search-path mutation on the provenance-checked resolver path.
        // Bootstrap needs to anchor these calls to the genuine backing module
        // before loading redist DLLs.
        const SetDefaultDllDirectoriesFn set_default_dll_directories =
            ResolveSystemPrimitive<SetDefaultDllDirectoriesFn>(kSetDefaultDllDirectoriesHash);
        if (set_default_dll_directories == nullptr ||
            !set_default_dll_directories(
                LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS)) {
            return {false, ErrorCode::BootstrapDllDirs};
        }

        const AddDllDirectoryFn add_dll_directory =
            ResolveSystemPrimitive<AddDllDirectoryFn>(kAddDllDirectoryHash);
        if (add_dll_directory == nullptr) {
            return {false, ErrorCode::BootstrapAddDir};
        }

        pending_cookie = add_dll_directory(canonical_directory.c_str());
        if (pending_cookie == nullptr) {
            return {false, ErrorCode::BootstrapAddDir};
        }
    }

    const LoadLibraryExWFn load_library_ex_w =
        ResolveSystemPrimitive<LoadLibraryExWFn>(kLoadLibraryExWHash);
    if (load_library_ex_w == nullptr) {
        rollback();
        return {false, ErrorCode::BootstrapLoad};
    }

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
            rollback();
            return {false, ErrorCode::InvalidBootstrapDependency};
        }

        if (config.integrity_provider) {
            bool ok = false;
            try {
                ok = config.integrity_provider(full_path, dll_name);
            } catch (...) {
                rollback();
                return {false, ErrorCode::CallbackFailed};
            }
            if (!ok) {
                rollback();
                return {false, ErrorCode::BootstrapIntegrityMismatch};
            }
        }

        // Resolve the actual loader entrypoint from the system images, then use it
        // directly for dependency loading. Path verification stays on the Win32 APIs
        // after the module is loaded because those checks are not the bootstrap trust root.
        HMODULE module = load_library_ex_w(
            full_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        if (module == nullptr) {
            rollback();
            return {false, ErrorCode::BootstrapLoad};
        }

        wchar_t loaded_path[MAX_PATH] = {};
        const DWORD n = ::GetModuleFileNameW(module, loaded_path, MAX_PATH);
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
            !PathsEqualCaseInsensitive(std::filesystem::path(loaded_path), full_path) ||
            !SameFileIdentity(locked_file.get(), loaded_file.get())) {
            ::FreeLibrary(module);
            rollback();
            return {false, ErrorCode::BootstrapModulePath};
        }

        pending_modules.push_back(MakeModuleLease(module, dll_name));

    }

    // Security-hook side effects are intentionally delayed until every module
    // has passed validation. A failed transaction can then unload all pending
    // modules without leaving one-time hook state bound to an unpublished DLL.
    if (config.install_global_allocator_hooks) {
        if (!TryApplyOpenSSLHooks()) {
            rollback();
            return {false, ErrorCode::AllocatorHookInstallFailed};
        }
#if BURNERNET_HARDEN_IMPORTS
        for (const auto& runtime_module : pending_modules) {
            const std::uint32_t basename_hash = ::burner::net::detail::fnv1a_ascii_wide_ci(
                runtime_module->basename.c_str(),
                runtime_module->basename.size());
            if (basename_hash == kLibCurlBootstrapHash ||
                basename_hash == kLibCurlDBootstrapHash) {
                CurlApi curl_api{};
                curl_api.global_init_mem = reinterpret_cast<CurlGlobalInitMemFn>(
                    ::burner::net::detail::KernelResolver::ResolveInternalExport(
                        runtime_module->handle,
                        ::burner::net::detail::kCurlGlobalInitMemHash));
                if (!EnsureCurlGlobalZapped(curl_api)) {
                    rollback();
                    return {false, ErrorCode::AllocatorHookInstallFailed};
                }
            }
        }
#endif
    }

    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        g_dependency_cookie = pending_cookie;
        pending_cookie = nullptr;
        g_loaded_modules = std::move(pending_modules);
        g_global_allocator_hooks_enabled.store(
            config.install_global_allocator_hooks,
            std::memory_order_release);
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
    DLL_DIRECTORY_COOKIE dependency_cookie = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_loader_mutex);
        if (g_bootstrap_in_progress) {
            return;
        }
        modules.swap(g_loaded_modules);
        dependency_cookie = g_dependency_cookie;
        g_dependency_cookie = nullptr;
        g_global_allocator_hooks_enabled.store(false, std::memory_order_release);
    }

    // Never execute DLL detach code while registry mutex is held. A module's
    // loader callback may otherwise re-enter runtime lookup and deadlock.
    ReleaseModulesReverse(modules);
    if (dependency_cookie) {
        const RemoveDllDirectoryFn remove_directory =
            ResolveSystemPrimitive<RemoveDllDirectoryFn>(kRemoveDllDirectoryHash);
        if (remove_directory) (void)remove_directory(dependency_cookie);
    }
}

} // namespace burner::net

#else

namespace burner::net {

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig&) {
    ::burner::net::detail::InitializeEncodedPointerKey();
    return {true, ErrorCode::BootstrapWinOnly};
}

void ShutdownNetworkingRuntime() noexcept {}
bool GlobalAllocatorHooksEnabled() noexcept { return false; }

} // namespace burner::net

#endif
