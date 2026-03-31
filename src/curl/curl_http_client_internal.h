#pragma once

#include "burner/net/http.h"

namespace burner::net {

struct BodyWriteContext {
    DarkString* body = nullptr;
    std::size_t max_body_bytes = 0;
    bool limit_exceeded = false;
    std::size_t streamed_body_bytes = 0;
    ChunkCallback on_chunk_received;
};

} // namespace burner::net
