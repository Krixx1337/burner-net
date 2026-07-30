#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"

TEST_CASE("Maximum Ghost requires bootstrap and remains active until process exit") {
#if !defined(_WIN32) || !BURNERNET_MAXIMUM_GHOST
    MESSAGE("Maximum Ghost lifecycle is Windows-only and requires the build option");
#else
    using namespace burner::net;

    REQUIRE_FALSE(GlobalAllocatorHooksEnabled());

    const auto unavailable = ClientBuilder().Build();
    REQUIRE_FALSE(unavailable.Ok());
    REQUIRE(unavailable.error == ErrorCode::MaximumGhostRuntimeRequired);

    BootstrapConfig boot{};
    boot.link_mode = LinkMode::Static;
    const auto initialized = InitializeNetworkingRuntime(boot);
    REQUIRE(initialized.success);
    REQUIRE(initialized.code == ErrorCode::BootstrapSkip);
    REQUIRE(GlobalAllocatorHooksEnabled());

    const auto repeated = InitializeNetworkingRuntime(boot);
    REQUIRE(repeated.success);
    REQUIRE(repeated.code == ErrorCode::BootstrapSkip);
    REQUIRE(GlobalAllocatorHooksEnabled());

    auto client = ClientBuilder().Build();
    REQUIRE(client.Ok());

    ShutdownNetworkingRuntime();
    REQUIRE(GlobalAllocatorHooksEnabled());

    auto after_shutdown = ClientBuilder().Build();
    REQUIRE(after_shutdown.Ok());
#endif
}
