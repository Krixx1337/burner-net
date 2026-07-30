#include "burner/net/bootstrap.h"

#if defined(_WIN32)
#define BURNERNET_TEST_EXPORT extern "C" __declspec(dllexport)
#else
#define BURNERNET_TEST_EXPORT extern "C"
#endif

BURNERNET_TEST_EXPORT int InitializeMaximumGhostFromSharedConsumer() {
#if !defined(_WIN32) || !BURNERNET_MAXIMUM_GHOST
    return 1;
#else
    burner::net::BootstrapConfig boot{};
    boot.link_mode = burner::net::LinkMode::Static;
    const auto initialized = burner::net::InitializeNetworkingRuntime(boot);
    return initialized.success &&
            burner::net::GlobalAllocatorHooksEnabled()
        ? 0
        : 2;
#endif
}
