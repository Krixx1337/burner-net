#pragma once

#include <cstddef>

namespace burner::net::detail::alloc {

// Metadata header prepended to every allocation.
// alignas(16) ensures OpenSSL SIMD instructions do not crash when given
// the offset user pointer.
struct alignas(16) AllocHeader {
    std::size_t requested_size;
};

static_assert(alignof(AllocHeader) == 16, "AllocHeader must stay 16-byte aligned.");
static_assert(sizeof(AllocHeader) % alignof(AllocHeader) == 0,
              "AllocHeader size must preserve user-pointer alignment.");

// C-linkage-compatible allocator callbacks suitable for passing to
// libcurl (CURLOPT_SHARE / curl_global_init_mem) and OpenSSL
// (CRYPTO_set_mem_functions).

void* dark_malloc(std::size_t size) noexcept;
void  dark_free(void* ptr) noexcept;
void* dark_realloc(void* ptr, std::size_t new_size) noexcept;
void* dark_calloc(std::size_t nmemb, std::size_t size) noexcept;
char* dark_strdup(const char* str) noexcept;

} // namespace burner::net::detail::alloc
