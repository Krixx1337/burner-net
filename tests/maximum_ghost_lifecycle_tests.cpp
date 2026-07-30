#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"

int main() {
#if !defined(_WIN32) || !BURNERNET_MAXIMUM_GHOST
    return 0;
#else
    using namespace burner::net;

    if (GlobalAllocatorHooksEnabled()) {
        return 1;
    }

    const auto unavailable = ClientBuilder().Build();
    if (unavailable.Ok() ||
        unavailable.error != ErrorCode::MaximumGhostRuntimeRequired) {
        return 2;
    }

    BootstrapConfig boot{};
    boot.link_mode = LinkMode::Static;
    const auto initialized = InitializeNetworkingRuntime(boot);
    if (!initialized.success ||
        initialized.code != ErrorCode::BootstrapSkip ||
        !GlobalAllocatorHooksEnabled()) {
        return 3;
    }

    const auto repeated = InitializeNetworkingRuntime(boot);
    if (!repeated.success ||
        repeated.code != ErrorCode::BootstrapSkip ||
        !GlobalAllocatorHooksEnabled()) {
        return 4;
    }

    auto client = ClientBuilder().Build();
    if (!client.Ok()) {
        return 5;
    }

    ShutdownNetworkingRuntime();
    if (!GlobalAllocatorHooksEnabled()) {
        return 6;
    }

    auto after_shutdown = ClientBuilder().Build();
    if (!after_shutdown.Ok()) {
        return 7;
    }

    return 0;
#endif
}
