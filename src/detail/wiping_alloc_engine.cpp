#include "burner/net/detail/wiping_alloc_engine.h"
#include "burner/net/detail/memory_hygiene.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace burner::net::detail::alloc {

// ---------------------------------------------------------------------------
// dark_malloc
// ---------------------------------------------------------------------------
void* dark_malloc(std::size_t size) noexcept {
    if (size == 0) {
        return nullptr;
    }

    const std::size_t total_size = sizeof(AllocHeader) + size;
    void* base = std::malloc(total_size);
    if (base == nullptr) {
        return nullptr;
    }

    auto* header = static_cast<AllocHeader*>(base);
    header->requested_size = size;

    return static_cast<std::byte*>(base) + sizeof(AllocHeader);
}

// ---------------------------------------------------------------------------
// dark_free
// ---------------------------------------------------------------------------
void dark_free(void* ptr) noexcept {
    if (ptr == nullptr) {
        return;
    }

    void* base = static_cast<std::byte*>(ptr) - sizeof(AllocHeader);
    const auto* header = static_cast<const AllocHeader*>(base);
    const std::size_t requested_size = header->requested_size;

    // Wipe the user-data area before returning memory to the OS.
    burner::net::obf::secure_wipe(ptr, requested_size);

    std::free(base);
}

// ---------------------------------------------------------------------------
// dark_calloc
// ---------------------------------------------------------------------------
void* dark_calloc(std::size_t nmemb, std::size_t size) noexcept {
    const std::size_t total = nmemb * size;
    void* ptr = dark_malloc(total);
    if (ptr != nullptr) {
        std::memset(ptr, 0, total);
    }
    return ptr;
}

// ---------------------------------------------------------------------------
// dark_strdup
// ---------------------------------------------------------------------------
char* dark_strdup(const char* str) noexcept {
    if (str == nullptr) {
        return nullptr;
    }

    const std::size_t len = std::strlen(str) + 1;
    void* ptr = dark_malloc(len);
    if (ptr != nullptr) {
        std::memcpy(ptr, str, len);
    }
    return static_cast<char*>(ptr);
}

// ---------------------------------------------------------------------------
// dark_realloc
// Implemented manually: system realloc would call the OS free on the old
// block without zeroing it, leaving a RAM Ghost at the original address.
// ---------------------------------------------------------------------------
void* dark_realloc(void* ptr, std::size_t new_size) noexcept {
    if (ptr == nullptr) {
        return dark_malloc(new_size);
    }

    if (new_size == 0) {
        dark_free(ptr);
        return nullptr;
    }

    // Recover the old size from the prefix header.
    const auto* header = reinterpret_cast<const AllocHeader*>(
        static_cast<std::byte*>(ptr) - sizeof(AllocHeader));
    const std::size_t old_size = header->requested_size;

    if (new_size == old_size) {
        return ptr;
    }

    void* new_ptr = dark_malloc(new_size);
    if (new_ptr == nullptr) {
        // Per POSIX: on failure the original ptr remains valid.
        return nullptr;
    }

    std::memcpy(new_ptr, ptr, std::min(old_size, new_size));

    // Securely wipe and release the old allocation.
    dark_free(ptr);

    return new_ptr;
}

} // namespace burner::net::detail::alloc
