#include <iostream>

#include "burner/net/builder.h"
#include "burner/net/error.h"

// This example assumes BurnerNet itself was compiled with a custom policy header.
//
// CMake:
//   target_include_directories(BurnerNet PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/templates)
//   target_compile_definitions(BurnerNet PRIVATE
//       BURNERNET_SECURITY_POLICY_HEADER=\"BurnerNet_SecurityPolicy.example.h\")
//
// Visual Studio:
//   1. Add the templates/ directory to Additional Include Directories for the
//      BurnerNet project.
//   2. Add this preprocessor definition to the BurnerNet project:
//      BURNERNET_SECURITY_POLICY_HEADER="BurnerNet_SecurityPolicy.example.h"
//
// Defining the macro only on the app project is not enough. BurnerNet itself
// has to be compiled with the policy header visible.

int main() {
    burner::net::ErrorCode build_error = burner::net::ErrorCode::None;
    auto client = burner::net::ClientBuilder()
        .WithUseNativeCa(true)
        .Build(&build_error);

    if (client == nullptr) {
        std::cerr << "failed to build client: "
                  << burner::net::ErrorCodeToString(build_error) << '\n';
        return 1;
    }

    std::cout << "Custom security policy example initialized.\n";
    std::cout << "If your policy rejects a remote IP in OnVerifyTransport,\n";
    std::cout << "BurnerNet will fail the request with TransportVerificationFailed.\n";
    return 0;
}
