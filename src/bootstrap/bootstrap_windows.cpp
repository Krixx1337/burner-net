#include "burner/net/bootstrap.h"
#include "burner/net/obfuscation.h"
#include "detail/hostile_imports.h"

#ifdef _WIN32
#if !BURNERNET_HARDEN_IMPORTS
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#include <windows.h>
#include <algorithm>
#include <cwctype>
#include <mutex>
#include <vector>

namespace burner::net {

namespace {

std::mutex g_loader_mutex;
std::vector<HMODULE> g_loaded_modules;
DLL_DIRECTORY_COOKIE g_dependency_cookie = nullptr;

using SetDefaultDllDirectoriesFn = decltype(&SetDefaultDllDirectories);
using AddDllDirectoryFn = decltype(&AddDllDirectory);
using LoadLibraryExWFn = decltype(&LoadLibraryExW);
using GetModuleFileNameWFn = decltype(&GetModuleFileNameW);
using FreeLibraryFn = decltype(&FreeLibrary);

struct LoaderImports {
    SetDefaultDllDirectoriesFn set_default_dll_directories = nullptr;
    AddDllDirectoryFn add_dll_directory = nullptr;
    LoadLibraryExWFn load_library_ex_w = nullptr;
    GetModuleFileNameWFn get_module_file_name_w = nullptr;

    [[nodiscard]] bool Ready() const {
        return set_default_dll_directories != nullptr && add_dll_directory != nullptr &&
            load_library_ex_w != nullptr && get_module_file_name_w != nullptr;
    }
};

const LoaderImports& GetLoaderImports() {
    static const LoaderImports imports{
        BURNER_LAZY_IMPORT_IN(SetDefaultDllDirectoriesFn, "kernel32.dll", SetDefaultDllDirectories),
        BURNER_LAZY_IMPORT_IN(AddDllDirectoryFn, "kernel32.dll", AddDllDirectory),
        BURNER_LAZY_IMPORT_IN(LoadLibraryExWFn, "kernel32.dll", LoadLibraryExW),
        BURNER_LAZY_IMPORT_IN(GetModuleFileNameWFn, "kernel32.dll", GetModuleFileNameW),
    };
    return imports;
}

FreeLibraryFn ResolveFreeLibrary() {
    return BURNER_LAZY_IMPORT_IN(FreeLibraryFn, "kernel32.dll", FreeLibrary);
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

} // namespace

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config) {
    const SecurityPolicy& security_policy = config.security_policy;
    if (config.link_mode == LinkMode::Static || !config.preload_dependencies) {
        return {true, ErrorCode::BootstrapSkip};
    }

    if (config.dependency_directory.empty()) {
        return {false, ErrorCode::BootstrapConfig};
    }

    if (!security_policy.OnVerifyEnvironment()) {
        return {false, ErrorCode::EnvironmentCompromised};
    }

    std::lock_guard<std::mutex> lock(g_loader_mutex);

    const LoaderImports& loader_imports = GetLoaderImports();
    if (!loader_imports.Ready()) {
        return {false, ErrorCode::BootstrapDllDirs};
    }
    const FreeLibraryFn free_library = ResolveFreeLibrary();
    if (free_library == nullptr) {
        return {false, ErrorCode::BootstrapLoad};
    }

    if (g_dependency_cookie == nullptr) {
        if (!loader_imports.set_default_dll_directories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS)) {
            return {false, ErrorCode::BootstrapDllDirs};
        }
        g_dependency_cookie = loader_imports.add_dll_directory(config.dependency_directory.c_str());
        if (g_dependency_cookie == nullptr) {
            return {false, ErrorCode::BootstrapAddDir};
        }
    }

    for (const auto& dll_name : config.dependency_dlls) {
        const std::filesystem::path full_path = config.dependency_directory / dll_name;

        if (config.integrity_policy.enabled) {
            if (!config.integrity_policy.integrity_provider) {
                if (config.integrity_policy.fail_closed) {
                    return {false, ErrorCode::BootstrapIntegrityCfg};
                }
            } else {
                const bool ok = config.integrity_policy.integrity_provider(full_path, dll_name);
                if (!ok && config.integrity_policy.fail_closed) {
                    return {false, ErrorCode::BootstrapIntegrityMismatch};
                }
            }
        }

        HMODULE module = loader_imports.load_library_ex_w(
            full_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);

        if (module == nullptr) {
            return {false, ErrorCode::BootstrapLoad};
        }

        wchar_t loaded_path[MAX_PATH] = {};
        const DWORD n = loader_imports.get_module_file_name_w(module, loaded_path, MAX_PATH);
        if (n == 0 || n == MAX_PATH || !PathsEqualCaseInsensitive(std::filesystem::path(loaded_path), full_path)) {
            free_library(module);
            return {false, ErrorCode::BootstrapModulePath};
        }

        g_loaded_modules.push_back(module);
    }

    return {true, ErrorCode::BootstrapLoaded};
}

} // namespace burner::net

#else

namespace burner::net {

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig&) {
    return {true, ErrorCode::BootstrapWinOnly};
}

} // namespace burner::net

#endif
