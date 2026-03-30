#include "burner/net/bootstrap.h"
#include "burner/net/obfuscation.h"
#include "detail/hostile_imports.h"

#ifdef _WIN32
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
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

using SetDefaultDllDirectoriesFn = decltype(&SetDefaultDllDirectories);
using AddDllDirectoryFn = decltype(&AddDllDirectory);
using LoadLibraryExWFn = decltype(&LoadLibraryExW);
using GetModuleFileNameWFn = decltype(&GetModuleFileNameW);
using CreateFileWFn = decltype(&CreateFileW);
using ReadFileFn = decltype(&ReadFile);
using CloseHandleFn = decltype(&CloseHandle);
using FreeLibraryFn = decltype(&FreeLibrary);
using BCryptOpenAlgorithmProviderFn = decltype(&BCryptOpenAlgorithmProvider);
using BCryptGetPropertyFn = decltype(&BCryptGetProperty);
using BCryptCreateHashFn = decltype(&BCryptCreateHash);
using BCryptHashDataFn = decltype(&BCryptHashData);
using BCryptFinishHashFn = decltype(&BCryptFinishHash);
using BCryptDestroyHashFn = decltype(&BCryptDestroyHash);
using BCryptCloseAlgorithmProviderFn = decltype(&BCryptCloseAlgorithmProvider);

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

CreateFileWFn ResolveCreateFileW() {
    return BURNER_LAZY_IMPORT_IN(CreateFileWFn, "kernel32.dll", CreateFileW);
}

ReadFileFn ResolveReadFile() {
    return BURNER_LAZY_IMPORT_IN(ReadFileFn, "kernel32.dll", ReadFile);
}

CloseHandleFn ResolveCloseHandle() {
    return BURNER_LAZY_IMPORT_IN(CloseHandleFn, "kernel32.dll", CloseHandle);
}

FreeLibraryFn ResolveFreeLibrary() {
    return BURNER_LAZY_IMPORT_IN(FreeLibraryFn, "kernel32.dll", FreeLibrary);
}

BCryptOpenAlgorithmProviderFn ResolveBCryptOpenAlgorithmProvider() {
    return BURNER_LAZY_IMPORT_IN(BCryptOpenAlgorithmProviderFn, "bcrypt.dll", BCryptOpenAlgorithmProvider);
}

BCryptGetPropertyFn ResolveBCryptGetProperty() {
    return BURNER_LAZY_IMPORT_IN(BCryptGetPropertyFn, "bcrypt.dll", BCryptGetProperty);
}

BCryptCreateHashFn ResolveBCryptCreateHash() {
    return BURNER_LAZY_IMPORT_IN(BCryptCreateHashFn, "bcrypt.dll", BCryptCreateHash);
}

BCryptHashDataFn ResolveBCryptHashData() {
    return BURNER_LAZY_IMPORT_IN(BCryptHashDataFn, "bcrypt.dll", BCryptHashData);
}

BCryptFinishHashFn ResolveBCryptFinishHash() {
    return BURNER_LAZY_IMPORT_IN(BCryptFinishHashFn, "bcrypt.dll", BCryptFinishHash);
}

BCryptDestroyHashFn ResolveBCryptDestroyHash() {
    return BURNER_LAZY_IMPORT_IN(BCryptDestroyHashFn, "bcrypt.dll", BCryptDestroyHash);
}

BCryptCloseAlgorithmProviderFn ResolveBCryptCloseAlgorithmProvider() {
    return BURNER_LAZY_IMPORT_IN(BCryptCloseAlgorithmProviderFn, "bcrypt.dll", BCryptCloseAlgorithmProvider);
}

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

    const CreateFileWFn create_file_w = ResolveCreateFileW();
    const ReadFileFn read_file = ResolveReadFile();
    const CloseHandleFn close_handle = ResolveCloseHandle();
    const BCryptOpenAlgorithmProviderFn bcrypt_open_algorithm_provider = ResolveBCryptOpenAlgorithmProvider();
    const BCryptGetPropertyFn bcrypt_get_property = ResolveBCryptGetProperty();
    const BCryptCreateHashFn bcrypt_create_hash = ResolveBCryptCreateHash();
    const BCryptHashDataFn bcrypt_hash_data = ResolveBCryptHashData();
    const BCryptFinishHashFn bcrypt_finish_hash = ResolveBCryptFinishHash();
    const BCryptDestroyHashFn bcrypt_destroy_hash = ResolveBCryptDestroyHash();
    const BCryptCloseAlgorithmProviderFn bcrypt_close_algorithm_provider = ResolveBCryptCloseAlgorithmProvider();
    if (create_file_w == nullptr || read_file == nullptr || close_handle == nullptr ||
        bcrypt_open_algorithm_provider == nullptr || bcrypt_get_property == nullptr ||
        bcrypt_create_hash == nullptr || bcrypt_hash_data == nullptr ||
        bcrypt_finish_hash == nullptr || bcrypt_destroy_hash == nullptr ||
        bcrypt_close_algorithm_provider == nullptr) {
        return false;
    }

    HANDLE file = create_file_w(
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
    NTSTATUS st = bcrypt_open_algorithm_provider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!nt_ok(st)) {
        close_handle(file);
        return false;
    }

    DWORD obj_len = 0;
    DWORD cb = 0;
    st = bcrypt_get_property(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len), &cb, 0);
    if (!nt_ok(st) || obj_len == 0) {
        bcrypt_close_algorithm_provider(alg, 0);
        close_handle(file);
        return false;
    }

    DWORD hash_len = 0;
    st = bcrypt_get_property(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);
    if (!nt_ok(st) || hash_len == 0) {
        bcrypt_close_algorithm_provider(alg, 0);
        close_handle(file);
        return false;
    }

    obj.resize(obj_len);
    digest.resize(hash_len);
    st = bcrypt_create_hash(alg, &hash, obj.data(), static_cast<ULONG>(obj.size()), nullptr, 0, 0);
    if (!nt_ok(st)) {
        bcrypt_close_algorithm_provider(alg, 0);
        close_handle(file);
        return false;
    }

    std::vector<UCHAR> buffer(64 * 1024);
    DWORD read = 0;
    BOOL ok = TRUE;
    while ((ok = read_file(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) && read > 0) {
        st = bcrypt_hash_data(hash, buffer.data(), read, 0);
        if (!nt_ok(st)) {
            burner::net::SecureWipe(buffer);
            burner::net::SecureWipe(digest);
            burner::net::SecureWipe(obj);
            bcrypt_destroy_hash(hash);
            bcrypt_close_algorithm_provider(alg, 0);
            close_handle(file);
            return false;
        }
    }
    if (!ok) {
        burner::net::SecureWipe(buffer);
        burner::net::SecureWipe(digest);
        burner::net::SecureWipe(obj);
        bcrypt_destroy_hash(hash);
        bcrypt_close_algorithm_provider(alg, 0);
        close_handle(file);
        return false;
    }

    st = bcrypt_finish_hash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    bcrypt_destroy_hash(hash);
    bcrypt_close_algorithm_provider(alg, 0);
    close_handle(file);
    if (!nt_ok(st)) {
        burner::net::SecureWipe(buffer);
        burner::net::SecureWipe(digest);
        burner::net::SecureWipe(obj);
        return false;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    out_hex.reserve(digest.size() * 2);
    for (const UCHAR b : digest) {
        out_hex.push_back(kHex[(b >> 4) & 0x0F]);
        out_hex.push_back(kHex[b & 0x0F]);
    }
    burner::net::SecureWipe(buffer);
    burner::net::SecureWipe(digest);
    burner::net::SecureWipe(obj);
    return true;
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
