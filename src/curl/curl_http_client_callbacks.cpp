#include "curl_http_client.h"

#include "curl_http_client_internal.h"
#include "curl_session.h"

#include <limits>

#ifdef _WIN32
#include <windows.h>
#endif

namespace burner::net {

size_t CurlHttpClient::WriteBodyCallback(void* contents, size_t size, size_t nmemb, void* user_data) {
    if (size > 0 && nmemb > ((std::numeric_limits<size_t>::max)() / size)) {
        return 0;
    }
    const size_t total = size * nmemb;
    if (user_data == nullptr || contents == nullptr) {
        return total;
    }

    auto* ctx = static_cast<BodyWriteContext*>(user_data);
    if (ctx->body == nullptr) {
        return 0;
    }

    if (total > (std::numeric_limits<std::size_t>::max)() - ctx->streamed_body_bytes) {
        ctx->limit_exceeded = true;
        return 0;
    }
    ctx->streamed_body_bytes += total;

    if (detail::WouldExceedBodyLimit(ctx->streamed_body_bytes - total, total, ctx->max_body_bytes)) {
        ctx->limit_exceeded = true;
        return 0;
    }

    if (ctx->on_chunk_received) {
        try {
            ctx->on_chunk_received(reinterpret_cast<const uint8_t*>(contents), total);
            return total;
        } catch (...) {
            if (ctx->callback_failed != nullptr) {
                *ctx->callback_failed = true;
            }
            return 0;
        }
    }

    try {
        ctx->body->append(static_cast<const char*>(contents), total);
        return total;
    } catch (...) {
        if (ctx->callback_failed != nullptr) {
            *ctx->callback_failed = true;
        }
        return 0;
    }
}

size_t CurlHttpClient::WriteHeaderCallback(void* contents, size_t size, size_t nmemb, void* user_data) {
    if (size > 0 && nmemb > ((std::numeric_limits<size_t>::max)() / size)) {
        return 0;
    }
    const size_t total = size * nmemb;
    if (user_data == nullptr || contents == nullptr) {
        return total;
    }

    auto* ctx = static_cast<HeaderWriteContext*>(user_data);
    if (ctx->headers == nullptr) {
        return 0;
    }
    if (total > (std::numeric_limits<std::size_t>::max)() - ctx->received_header_bytes ||
        ctx->received_header_bytes + total > ctx->max_header_bytes) {
        ctx->limit_exceeded = true;
        return 0;
    }
    ctx->received_header_bytes += total;
    std::string_view line(static_cast<const char*>(contents), total);

    try {
        if (line.starts_with("HTTP/")) {
            ctx->headers->clear();
            return total;
        }

        auto it = line.find(':');
        if (it != std::string_view::npos) {
            if (ctx->received_header_count >= ctx->max_header_count) {
                ctx->limit_exceeded = true;
                return 0;
            }
            ++ctx->received_header_count;
            DarkString name(line.substr(0, it));
            DarkString value(line.substr(it + 1));

            auto trim = [](DarkString& x) {
                while (!x.empty() && (x.back() == '\r' || x.back() == '\n' || x.back() == ' ' || x.back() == '\t')) {
                    x.pop_back();
                }
                size_t start = 0;
                while (start < x.size() && (x[start] == ' ' || x[start] == '\t')) {
                    ++start;
                }
                if (start > 0) {
                    x.erase(0, start);
                }
            };

            trim(name);
            trim(value);

            if (!name.empty()) {
                ctx->headers->insert_or_assign(std::move(name), std::move(value));
            }
        }
        return total;
    } catch (...) {
        if (ctx->callback_failed != nullptr) {
            *ctx->callback_failed = true;
        }
        return 0;
    }
}

size_t CurlHttpClient::ReadBodyCallback(char* buffer, size_t size, size_t nmemb, void* user_data) {
    if (size > 0 && nmemb > ((std::numeric_limits<size_t>::max)() / size)) {
        return CURL_READFUNC_ABORT;
    }

    const size_t total = size * nmemb;
    if (buffer == nullptr || user_data == nullptr) {
        return total == 0 ? 0 : CURL_READFUNC_ABORT;
    }

    auto* ctx = static_cast<BodyReadContext*>(user_data);
    if (ctx->provider == nullptr || !(*ctx->provider)) {
        return CURL_READFUNC_ABORT;
    }

    try {
        const size_t produced = (*ctx->provider)(std::span<char>(buffer, total));
        if (produced <= total) {
            return produced;
        }
        if (ctx->callback_failed != nullptr) {
            *ctx->callback_failed = true;
        }
        return CURL_READFUNC_ABORT;
    } catch (...) {
        if (ctx->callback_failed != nullptr) {
            *ctx->callback_failed = true;
        }
        return CURL_READFUNC_ABORT;
    }
}

int CurlHttpClient::ProgressCallback(void* clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    auto* self = static_cast<CurlHttpClient*>(clientp);
    if (self == nullptr) {
        return 0;
    }

    const TransferProgress progress{
        static_cast<long long>(dltotal),
        static_cast<long long>(dlnow),
        static_cast<long long>(ultotal),
        static_cast<long long>(ulnow),
    };

    if (self->m_config.transfer_cancellation) {
        try {
            if (!self->m_config.transfer_cancellation(progress)) {
                self->m_transfer_cancelled = true;
                return 1;
            }
        } catch (...) {
            self->m_callback_failed = true;
            return 1;
        }
    }

    return 0;
}

void CurlHttpClient::WipeResponse(HttpResponse& response) const {
    response.ClearSensitiveData();
}

} // namespace burner::net
