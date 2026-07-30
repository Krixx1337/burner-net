#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"

#include <curl/curl.h>

namespace {

struct CurlGlobalCleanupGuard final {
    ~CurlGlobalCleanupGuard() {
        curl_global_cleanup();
    }
};

} // namespace

TEST_CASE("Maximum Ghost tolerates host-owned curl initialization") {
#if !defined(_WIN32) || !BURNERNET_MAXIMUM_GHOST || BURNERNET_HARDEN_IMPORTS
    MESSAGE("Late linked-hook test requires Windows Maximum Ghost without hardened imports");
#else
    using namespace burner::net;

    REQUIRE(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK);
    const CurlGlobalCleanupGuard cleanup_guard;

    BootstrapConfig boot{};
    boot.link_mode = LinkMode::Static;
    const auto late = InitializeNetworkingRuntime(boot);
    REQUIRE(late.success);
    REQUIRE(late.code == ErrorCode::BootstrapSkip);
    REQUIRE_FALSE(GlobalAllocatorHooksEnabled());

    const auto repeated = InitializeNetworkingRuntime(boot);
    REQUIRE(repeated.success);
    REQUIRE(repeated.code == ErrorCode::BootstrapSkip);

    const auto available = ClientBuilder().Build();
    REQUIRE(available.Ok());

    ShutdownNetworkingRuntime();
#endif
}
