#include "burner/net/bootstrap.h"
#include "burner/net/detail/hostile_imports.h"
#include "../error_strings.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <mutex>
#include <vector>

namespace burner::net {

namespace {

std::mutex g_loader_mutex;
std::vector<HMODULE> g_loaded_modules;
DLL_DIRECTORY_COOKIE g_dependency_cookie = nullptr;

using SetDefaultDllDirectoriesFn = BOOL(WINAPI*)(DWORD);
using AddDllDirectoryFn = DLL_DIRECTORY_COOKIE(WINAPI*)(PCWSTR);
using LoadLibraryExWFn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using GetModuleFileNameWFn = DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD);

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

#if BURNERNET_HARDEN_IMPORTS
const LoaderImports& GetLoaderImports() {
    static const LoaderImports imports{
        BURNER_HOSTILE_IMPORT(SetDefaultDllDirectoriesFn, "kernel32.dll", "SetDefaultDllDirectories"),
        BURNER_HOSTILE_IMPORT(AddDllDirectoryFn, "kernel32.dll", "AddDllDirectory"),
        BURNER_HOSTILE_IMPORT(LoadLibraryExWFn, "kernel32.dll", "LoadLibraryExW"),
        BURNER_HOSTILE_IMPORT(GetModuleFileNameWFn, "kernel32.dll", "GetModuleFileNameW"),
    };
    return imports;
}
#endif

std::wstring ToLowerWide(const std::wstring& value) {
    std::wstring out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return out;
}

std::string ToLowerAscii(const std::string& value) {
    std::string out = value;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });
    return out;
}

const DependencyHashEntry* FindAllowlistEntry(
    const DependencyIntegrityPolicy& policy,
    const std::wstring& dll_name) {
    const std::wstring needle = ToLowerWide(dll_name);
    for (const auto& entry : policy.sha256_allowlist) {
        if (ToLowerWide(entry.dll_name) == needle) {
            return &entry;
        }
    }
    return nullptr;
}

bool ComputeFileSha256Hex(const std::filesystem::path& path, std::string& out_hex) {
    out_hex.clear();

    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    const auto nt_ok = [](NTSTATUS status) { return status >= 0; };
    std::vector<UCHAR> obj;
    std::vector<UCHAR> digest;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!nt_ok(st)) {
        CloseHandle(file);
        return false;
    }

    DWORD obj_len = 0;
    DWORD cb = 0;
    st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (!nt_ok(st) || obj_len == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(file);
        return false;
    }

    DWORD hash_len = 0;
    st = BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);
    if (!nt_ok(st) || hash_len == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(file);
        return false;
    }

    obj.resize(obj_len);
    digest.resize(hash_len);
    st = BCryptCreateHash(alg, &hash, obj.data(), static_cast<ULONG>(obj.size()), nullptr, 0, 0);
    if (!nt_ok(st)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(file);
        return false;
    }

    std::vector<UCHAR> buffer(64 * 1024);
    DWORD read = 0;
    BOOL ok = TRUE;
    while ((ok = ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) && read > 0) {
        st = BCryptHashData(hash, buffer.data(), read, 0);
        if (!nt_ok(st)) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            CloseHandle(file);
            return false;
        }
    }
    if (!ok) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(file);
        return false;
    }

    st = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    if (!nt_ok(st)) {
        return false;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    out_hex.reserve(digest.size() * 2);
    for (const UCHAR b : digest) {
        out_hex.push_back(kHex[(b >> 4) & 0x0F]);
        out_hex.push_back(kHex[b & 0x0F]);
    }
    return true;
}

bool PathsEqualCaseInsensitive(const std::filesystem::path& a, const std::filesystem::path& b) {
    return ToLowerWide(a.wstring()) == ToLowerWide(b.wstring());
}

} // namespace

BootstrapResult InitializeNetworkingRuntime(const BootstrapConfig& config) {
    if (config.link_mode == LinkMode::Static || !config.preload_dependencies) {
        return {true, ErrorCode::BootstrapSkip};
    }

    if (config.dependency_directory.empty()) {
        return {false, ErrorCode::BootstrapConfig};
    }

    if (!detail::CallVerifyEnvironment<Security>()) {
        return {false, ErrorCode::EnvironmentCompromised};
    }

    std::lock_guard<std::mutex> lock(g_loader_mutex);

#if BURNERNET_HARDEN_IMPORTS
    const LoaderImports& loader_imports = GetLoaderImports();
    if (!loader_imports.Ready()) {
        return {false, ErrorCode::BootstrapDllDirs};
    }
#endif

    if (g_dependency_cookie == nullptr) {
#if BURNERNET_HARDEN_IMPORTS
        if (!loader_imports.set_default_dll_directories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS)) {
#else
        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS)) {
#endif
            return {false, ErrorCode::BootstrapDllDirs};
        }
#if BURNERNET_HARDEN_IMPORTS
        g_dependency_cookie = loader_imports.add_dll_directory(config.dependency_directory.c_str());
#else
        g_dependency_cookie = AddDllDirectory(config.dependency_directory.c_str());
#endif
        if (g_dependency_cookie == nullptr) {
            return {false, ErrorCode::BootstrapAddDir};
        }
    }

    for (const auto& dll_name : config.dependency_dlls) {
        const std::filesystem::path full_path = config.dependency_directory / dll_name;

        if (config.integrity_policy.enabled) {
            if (config.integrity_policy.sha256_allowlist.empty()) {
                if (config.integrity_policy.fail_closed) {
                    return {false, ErrorCode::BootstrapIntegrityCfg};
                }
            } else {
                const DependencyHashEntry* entry = FindAllowlistEntry(config.integrity_policy, dll_name);
                if (entry == nullptr) {
                    if (config.integrity_policy.fail_closed) {
                        return {false, ErrorCode::BootstrapIntegrityMissing};
                    }
                } else {
                    std::string hash_hex;
                    if (!ComputeFileSha256Hex(full_path, hash_hex)) {
                        if (config.integrity_policy.fail_closed) {
                            return {false, ErrorCode::BootstrapIntegrityCompute};
                        }
                    } else if (ToLowerAscii(hash_hex) != ToLowerAscii(entry->sha256_hex)) {
                        if (config.integrity_policy.fail_closed) {
                            return {false, ErrorCode::BootstrapIntegrityMismatch};
                        }
                    }
                }
            }
        }

#if BURNERNET_HARDEN_IMPORTS
        HMODULE module = loader_imports.load_library_ex_w(
            full_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
#else
        HMODULE module = LoadLibraryExW(
            full_path.c_str(),
            nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
#endif

        if (module == nullptr) {
            return {false, ErrorCode::BootstrapLoad};
        }

        wchar_t loaded_path[MAX_PATH] = {};
#if BURNERNET_HARDEN_IMPORTS
        const DWORD n = loader_imports.get_module_file_name_w(module, loaded_path, MAX_PATH);
#else
        const DWORD n = GetModuleFileNameW(module, loaded_path, MAX_PATH);
#endif
        if (n == 0 || n == MAX_PATH || !PathsEqualCaseInsensitive(std::filesystem::path(loaded_path), full_path)) {
            FreeLibrary(module);
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
