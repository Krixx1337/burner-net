#include "header_validation.h"

#include <cctype>
#include <string_view>

namespace burner::net::internal {

namespace {

bool ContainsCrlf(std::string_view value) {
    return value.find('\r') != std::string_view::npos || value.find('\n') != std::string_view::npos;
}

} // namespace

bool IsValidHeaderName(std::string_view name) {
    if (name.empty() || ContainsCrlf(name)) {
        return false;
    }

    for (const unsigned char c : name) {
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z')) {
            continue;
        }

        switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            continue;
        default:
            return false;
        }
    }

    return true;
}

bool IsValidHeaderValue(std::string_view value) {
    for (const unsigned char c : value) {
        if (c == '\t') {
            continue;
        }
        if (c < 0x20 || c == 0x7f) {
            return false;
        }
    }
    return true;
}

bool IsValidBearerToken(std::string_view token) {
    if (token.empty()) {
        return false;
    }
    bool padding_started = false;
    for (const unsigned char c : token) {
        if (c == '=') {
            padding_started = true;
            continue;
        }
        if (padding_started ||
            !((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              c == '-' || c == '.' || c == '_' || c == '~' ||
              c == '+' || c == '/')) {
            return false;
        }
    }
    return true;
}

bool IsValidHttpsUrl(std::string_view url) {
    constexpr std::string_view prefix = "https://";
    if (!url.starts_with(prefix)) {
        return false;
    }

    const std::string_view authority_and_path = url.substr(prefix.size());
    const std::size_t authority_end = authority_and_path.find_first_of("/?#");
    const std::string_view authority = authority_and_path.substr(0, authority_end);
    if (authority.empty() || authority.find('@') != std::string_view::npos) {
        return false;
    }
    for (const unsigned char c : url) {
        if (c <= 0x20 || c == 0x7f) {
            return false;
        }
    }
    return true;
}

} // namespace burner::net::internal
