#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"

#include <curl/curl.h>

int main() {
#if !defined(_WIN32) || !BURNERNET_MAXIMUM_GHOST || BURNERNET_HARDEN_IMPORTS
    return 0;
#else
    using namespace burner::net;

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        return 1;
    }

    BootstrapConfig boot{};
    boot.link_mode = LinkMode::Static;
    const auto late = InitializeNetworkingRuntime(boot);
    if (late.success ||
        late.code != ErrorCode::AllocatorHookInstallFailed ||
        GlobalAllocatorHooksEnabled()) {
        curl_global_cleanup();
        return 2;
    }

    const auto repeated = InitializeNetworkingRuntime(boot);
    if (repeated.success ||
        repeated.code != ErrorCode::AllocatorHookInstallFailed) {
        curl_global_cleanup();
        return 3;
    }

    const auto unavailable = ClientBuilder().Build();
    if (unavailable.Ok() ||
        unavailable.error != ErrorCode::AllocatorHookInstallFailed) {
        curl_global_cleanup();
        return 4;
    }

    ShutdownNetworkingRuntime();
    curl_global_cleanup();
    return 0;
#endif
}
