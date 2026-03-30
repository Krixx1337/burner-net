#include "burner/net/detail/memory_hygiene.h"

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace burner::net::obf {

void secure_wipe(void* ptr, std::size_t size) noexcept {
    if (ptr == nullptr || size == 0) {
        return;
    }

#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#else
    volatile unsigned char* volatile_ptr = static_cast<volatile unsigned char*>(ptr);
    for (std::size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = 0;
    }
#endif
}

} // namespace burner::net::obf
