#pragma once

#ifdef _WIN32

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <intrin.h>
#include <windows.h>
#include <winternl.h>

#include "dark_hashing.h"

namespace burner::net::detail {

struct LDR_DATA_TABLE_ENTRY_INTERNAL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    std::uint32_t SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

class KernelResolver {
public:
    // BurnerNet prefers this resolver over generic lazy-import approaches because our
    // hardened path needs a single trust root we can reason about and extend.
    //
    // For this codebase, walking the PEB and parsing export tables directly is better:
    // 1. It keeps module discovery and export resolution inside BurnerNet instead of
    //    depending on third-party importer machinery with different assumptions.
    // 2. It gives us explicit provenance checks and section introspection on the same
    //    path that resolves function pointers, which lazy trampolines do not provide.
    // 3. It works as one consistent mechanism for core runtime loading, bootstrap, and
    //    user-facing examples, so the hardened path stays auditable and predictable.
    [[nodiscard]] static void* GetSystemModule(std::uint32_t module_hash) noexcept {
#ifdef _WIN64
        auto* peb = reinterpret_cast<std::uint8_t*>(__readgsqword(0x60));
        auto* ldr = *reinterpret_cast<std::uint8_t**>(peb + 0x18);
        auto* list_head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x10);
#else
        auto* peb = reinterpret_cast<std::uint8_t*>(__readfsdword(0x30));
        auto* ldr = *reinterpret_cast<std::uint8_t**>(peb + 0x0C);
        auto* list_head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x0C);
#endif
        for (auto* it = list_head->Flink; it != list_head; it = it->Flink) {
            auto* entry = CONTAINING_RECORD(it, LDR_DATA_TABLE_ENTRY_INTERNAL, InLoadOrderLinks);
            if (entry->BaseDllName.Buffer == nullptr || entry->BaseDllName.Length == 0) {
                continue;
            }

            const std::size_t length = entry->BaseDllName.Length / sizeof(wchar_t);
            const std::uint32_t hash = fnv1a_ascii_wide_ci(entry->BaseDllName.Buffer, length);
            if (hash == module_hash) {
                return entry->DllBase;
            }
        }

        return nullptr;
    }

    [[nodiscard]] static void* FindModuleSignature(void* module_base, std::uint8_t signature) noexcept {
        if (module_base == nullptr) {
            return nullptr;
        }

        auto* base = static_cast<std::uint8_t*>(module_base);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) {
            return nullptr;
        }

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        const std::size_t image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size == 0 || nt->FileHeader.NumberOfSections == 0) {
            return nullptr;
        }

        auto* section = IMAGE_FIRST_SECTION(nt);
        for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) {
                continue;
            }

            const std::size_t section_offset = static_cast<std::size_t>(section->VirtualAddress);
            const std::size_t declared_size = static_cast<std::size_t>(
                section->Misc.VirtualSize != 0 ? section->Misc.VirtualSize : section->SizeOfRawData);
            if (declared_size == 0 || section_offset >= image_size) {
                continue;
            }

            const std::size_t bounded_size = (declared_size > (image_size - section_offset))
                ? (image_size - section_offset)
                : declared_size;
            const auto* start = base + section_offset;
            const auto* end = start + bounded_size;

            for (const auto* p = start; p < end; ++p) {
                if (*p == signature) {
                    return const_cast<std::uint8_t*>(p);
                }
            }
        }

        return nullptr;
    }

    [[nodiscard]] static void* ResolveInternalExport(void* module_base, std::uint32_t func_hash) noexcept {
        return ResolveInternalExport(module_base, func_hash, 0);
    }

private:
    static constexpr std::uint32_t kKernel32Hash = fnv1a_ci("kernel32.dll");
    static constexpr std::uint32_t kKernelBaseHash = fnv1a_ci("kernelbase.dll");
    static constexpr std::uint32_t kNtDllHash = fnv1a_ci("ntdll.dll");

    [[nodiscard]] static void* ResolveInternalExport(void* module_base,
                                                     std::uint32_t func_hash,
                                                     std::uint32_t depth) noexcept {
        if (module_base == nullptr || depth > 2) {
            return nullptr;
        }

        auto* base = static_cast<std::uint8_t*>(module_base);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return nullptr;
        }

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return nullptr;
        }

        const IMAGE_DATA_DIRECTORY export_data =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (export_data.VirtualAddress == 0 || export_data.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
            return nullptr;
        }

        auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + export_data.VirtualAddress);
        auto* names = reinterpret_cast<std::uint32_t*>(base + exports->AddressOfNames);
        auto* ordinals = reinterpret_cast<std::uint16_t*>(base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<std::uint32_t*>(base + exports->AddressOfFunctions);

        for (std::uint32_t i = 0; i < exports->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(base + names[i]);
            if (fnv1a_runtime(std::string_view{name}) != func_hash) {
                continue;
            }

            const std::uint32_t function_rva = functions[ordinals[i]];
            const auto export_start = export_data.VirtualAddress;
            const auto export_end = export_start + export_data.Size;
            if (function_rva >= export_start && function_rva < export_end) {
                return ResolveForwardedExport(base, function_rva, depth + 1);
            }

            return base + function_rva;
        }

        return nullptr;
    }

    [[nodiscard]] static void* ResolveForwardedExport(std::uint8_t* source_base,
                                                      std::uint32_t forwarder_rva,
                                                      std::uint32_t depth) noexcept {
        const char* forwarder = reinterpret_cast<const char*>(source_base + forwarder_rva);
        std::string_view target{forwarder};

        const std::size_t dot = target.find('.');
        if (dot == std::string_view::npos || dot + 1 >= target.size()) {
            return nullptr;
        }

        const std::string_view module_name = target.substr(0, dot);
        const std::string_view export_name = target.substr(dot + 1);
        if (!export_name.empty() && export_name.front() == '#') {
            return nullptr;
        }

        const std::uint32_t module_hash = HashForwardedModule(module_name);
        if (module_hash == 0) {
            return nullptr;
        }

        return ResolveInternalExport(GetSystemModule(module_hash), fnv1a_runtime(export_name), depth);
    }

    [[nodiscard]] static std::uint32_t HashForwardedModule(std::string_view module_name) noexcept {
        if (module_name.empty()) {
            return 0;
        }

        if (module_name.find('.') == std::string_view::npos) {
            if (fnv1a_runtime_ci(module_name) == fnv1a_ci("kernel32")) {
                return kKernel32Hash;
            }
            if (fnv1a_runtime_ci(module_name) == fnv1a_ci("kernelbase")) {
                return kKernelBaseHash;
            }
            if (fnv1a_runtime_ci(module_name) == fnv1a_ci("ntdll")) {
                return kNtDllHash;
            }
            return 0;
        }

        const std::uint32_t module_hash = fnv1a_runtime_ci(module_name);
        if (module_hash == kKernel32Hash || module_hash == kKernelBaseHash || module_hash == kNtDllHash) {
            return module_hash;
        }

        return 0;
    }
};

} // namespace burner::net::detail

#endif
