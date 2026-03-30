#include "import_pointer_trust.h"

#ifdef _WIN32
#include <windows.h>
#include <cwchar>
#include <filesystem>
#endif

namespace burner::net::internal {

#ifdef _WIN32
namespace {

bool IsExecutableProtection(DWORD protect) {
    constexpr DWORD kIgnoredBits = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    const DWORD normalized = protect & ~kIgnoredBits;
    switch (normalized) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

} // namespace
#endif

bool IsFunctionPointerInAllowedModules(
    const void* fn,
    const std::vector<std::wstring>& allowed_module_basenames) {
#ifdef _WIN32
    if (fn == nullptr || allowed_module_basenames.empty()) {
        return false;
    }

    HMODULE owner_module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(fn),
            &owner_module)) {
        return false;
    }

    wchar_t module_path[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(owner_module, module_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }

    const std::wstring basename = std::filesystem::path(module_path).filename().wstring();
    if (basename.empty()) {
        return false;
    }

    for (const std::wstring& allowed : allowed_module_basenames) {
        if (!allowed.empty() && _wcsicmp(basename.c_str(), allowed.c_str()) == 0) {
            return true;
        }
    }

    return false;
#else
    (void)fn;
    (void)allowed_module_basenames;
    return false;
#endif
}

bool IsFunctionPointerExecutable(const void* fn) {
#ifdef _WIN32
    if (fn == nullptr) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(fn, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }

    if (mbi.State != MEM_COMMIT) {
        return false;
    }

    return IsExecutableProtection(mbi.Protect);
#else
    (void)fn;
    return false;
#endif
}

bool IsFunctionPointerTrusted(
    const void* fn,
    const std::vector<std::wstring>& allowed_module_basenames) {
    if (!IsFunctionPointerInAllowedModules(fn, allowed_module_basenames)) {
        return false;
    }
    if (!IsFunctionPointerExecutable(fn)) {
        return false;
    }
    return true;
}

} // namespace burner::net::internal
