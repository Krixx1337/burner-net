#if BURNER_ENABLE_CURL

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

    ctx->streamed_body_bytes += total;

    if (detail::WouldExceedBodyLimit(ctx->streamed_body_bytes - total, total, ctx->max_body_bytes)) {
        ctx->limit_exceeded = true;
        return 0;
    }

    if (ctx->on_chunk_received) {
        ctx->on_chunk_received(reinterpret_cast<const uint8_t*>(contents), total);
        return total;
    }

    ctx->body->append(static_cast<const char*>(contents), total);
    return total;
}

size_t CurlHttpClient::WriteHeaderCallback(void* contents, size_t size, size_t nmemb, void* user_data) {
    const size_t total = size * nmemb;
    if (user_data == nullptr || contents == nullptr) {
        return total;
    }

    auto* headers = static_cast<HeaderMap*>(user_data);
    std::string line(static_cast<const char*>(contents), total);

    auto it = line.find(':');
    if (it != std::string::npos) {
        std::string name = line.substr(0, it);
        std::string value = line.substr(it + 1);

        auto trim = [](std::string& x) {
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
            headers->insert_or_assign(std::move(name), std::move(value));
        }
    }

    SecureWipe(line);
    return total;
}

int CurlHttpClient::ProgressCallback(void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    auto* self = static_cast<CurlHttpClient*>(clientp);
    if (self == nullptr) {
        return 0;
    }

    if (!self->m_config.security_policy.OnHeartbeat()) {
        self->m_heartbeat_aborted = true;
        return 1;
    }

    return 0;
}

void CurlHttpClient::WipeResponse(HttpResponse& response) const {
    SecureWipe(response.body);
    response.headers.clear();
    response.streamed_body_bytes = 0;
}

void CurlHttpClient::WipeHeaderList(curl_slist* headers) const {
    for (curl_slist* it = headers; it != nullptr; it = it->next) {
        if (it->data != nullptr) {
            const size_t len = std::char_traits<char>::length(it->data);
#if defined(_WIN32)
            SecureZeroMemory(it->data, len);
#else
            volatile char* ptr = it->data;
            for (size_t i = 0; i < len; ++i) {
                ptr[i] = '\0';
            }
#endif
        }
    }

    if (headers != nullptr && m_session != nullptr) {
        m_session->Api().slist_free_all(headers);
    }
}

} // namespace burner::net

#endif
