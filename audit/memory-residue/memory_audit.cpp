#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <thread>
#include <utility>

#include "burner/net/bootstrap.h"
#include "burner/net/builder.h"
#include "burner/net/error.h"
#include "burner/net/obfuscation.h"
#include "burner/net/version.h"

#ifndef BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST
#define BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST 0
#endif

#if !defined(_WIN32) || !BURNERNET_HARDEN_IMPORTS || BURNERNET_DIAGNOSTIC_STRINGS
#error "Memory audit requires Windows, hardened imports, and diagnostic strings off"
#endif

#if BURNERNET_MEMORY_AUDIT_MAXIMUM_GHOST != BURNERNET_MAXIMUM_GHOST
#error "Audit mode and BurnerNet Maximum Ghost configuration disagree"
#endif

namespace {

bool InitializeRuntime(const char* executable) {
    burner::net::BootstrapConfig bootstrap{};
    bootstrap.link_mode = burner::net::LinkMode::Dynamic;
    bootstrap.dependency_directory =
        std::filesystem::absolute(executable).parent_path() / "redist";
    bootstrap.dependency_dlls.push_back(L"libcurl.dll");
    bootstrap.integrity_provider =
        [](const std::filesystem::path& path, const std::wstring&) {
            return std::filesystem::is_regular_file(path);
        };

    const auto initialized = burner::net::InitializeNetworkingRuntime(bootstrap);
    if (!initialized.success) {
        std::cerr << "Runtime initialization failed: "
                  << burner::net::ErrorCodeToString(initialized.code) << '\n';
        return false;
    }

#if BURNERNET_MAXIMUM_GHOST
    if (!burner::net::GlobalAllocatorHooksEnabled()) {
        std::cerr << "Audit refused: Maximum Ghost allocator hooks are inactive.\n";
        return false;
    }
#else
    if (burner::net::GlobalAllocatorHooksEnabled()) {
        std::cerr << "Audit refused: allocator hooks are active in the control build.\n";
        return false;
    }
#endif
    return true;
}

int RunAudit() {
    auto build_result = burner::net::ClientBuilder()
        .WithStackIsolation(true)
        .WithLoopbackPeerRejection()
        .Build();
    if (!build_result.Ok()) {
        std::cerr << "Client build failed: "
                  << burner::net::ErrorCodeToString(build_result.error) << '\n';
        return 1;
    }

    std::cout
        << "BurnerNet memory audit v" << burner::net::VersionString << '\n'
#if BURNERNET_MAXIMUM_GHOST
        << "Mode: Maximum Ghost ON.\n"
#else
        << "Mode: Maximum Ghost OFF (control).\n"
#endif
        << "Scan during each 10-second idle window. Press Ctrl+C to stop.\n"
        << std::flush;

    std::uint64_t cycle = 0;
    for (;;) {
        int status_code = 0;
        burner::net::ErrorCode transport_error = burner::net::ErrorCode::None;
        {
            auto audit_url =
                BURNER_OBF_LITERAL("https://example.com/burnernet-audit-url-canary-48291");
            const auto response = build_result.client
                ->Get(std::move(audit_url))
                .WithEphemeralToken([](burner::net::DarkString& output) {
                    auto token =
                        BURNER_OBF_LITERAL("burnernet-audit-token-canary-73915");
                    output.assign(token.begin(), token.end());
                    burner::net::SecureWipe(token);
                    return true;
                })
                .WithConnectTimeoutSeconds(5)
                .WithTimeoutSeconds(10)
                .FollowRedirects(false)
                .Send();
            status_code = response.status_code;
            transport_error = response.transport_error;
        }

        ++cycle;
        std::cout << "Cycle " << cycle
                  << " complete; status=" << status_code
                  << ", transport=" << static_cast<std::uint32_t>(transport_error)
                  << ". Idle window begins now.\n"
                  << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc <= 0 || argv == nullptr || argv[0] == nullptr ||
        !InitializeRuntime(argv[0])) {
        return 1;
    }
    return RunAudit();
}
