#pragma once

#include "burner/net/http.h"

#include <string_view>

namespace burner::net {

namespace detail {

DarkString MakeCacheExpiringResolveEntry(std::string_view entry);

} // namespace detail

struct BodyWriteContext {
    DarkString* body = nullptr;
    std::size_t max_body_bytes = 0;
    bool limit_exceeded = false;
    std::size_t streamed_body_bytes = 0;
    ChunkCallback on_chunk_received;
};

struct BodyReadContext {
    const StreamPayloadCallback* provider = nullptr;
};

} // namespace burner::net
