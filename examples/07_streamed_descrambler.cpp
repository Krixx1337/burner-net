#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>

#include "burner/net/builder.h"

int RunStreamedDescrambler() {
    using namespace burner::net;

    auto build_result = ClientBuilder()
        .WithUseNativeCa(true)
        .WithStackIsolation(true)
        .Build();

    if (!build_result.Ok()) {
        std::cerr << "Failed to build BurnerNet client\n";
        return 1;
    }

    constexpr std::array<std::uint8_t, 18> scrambled_payload = {
        0xd6, 0x87, 0xcd, 0xd0, 0xd6, 0xc0, 0xd7, 0x87, 0x9f,
        0x85, 0x94, 0x97, 0x96, 0x91, 0x90, 0x93, 0xd8, 0xa8
    };
    constexpr std::uint8_t xor_key = 0xA5;

    auto cursor = std::make_shared<std::size_t>(0);

    const auto response = build_result.client->Post("https://httpbin.org/post")
        .WithHeader("Content-Type", "application/json")
        .WithStreamedBody(scrambled_payload.size(),
            [cursor, &scrambled_payload, xor_key](std::span<char> dest) -> std::size_t {
                const std::size_t remaining = scrambled_payload.size() - *cursor;
                if (remaining == 0) {
                    return 0;
                }

                const std::size_t chunk = dest.size() < remaining ? dest.size() : remaining;
                for (std::size_t i = 0; i < chunk; ++i) {
                    dest[i] = static_cast<char>(scrambled_payload[*cursor + i] ^ xor_key);
                }

                *cursor += chunk;
                return chunk;
            })
        .Send();

    std::cout << "status=" << response.status_code
              << " transport=" << response.transport_code
              << " ok=" << response.Ok() << '\n';
    return response.Ok() ? 0 : 1;
}
