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
    for (const unsigned char c : token) {
        // Bearer credentials are opaque to the transport. Restricting them to
        // a specific token alphabet can reject valid application-defined
        // credentials before the request reaches curl.
        // Visible ASCII preserves the protocol contract while excluding all
        // whitespace and control characters, including CR/LF injection.
        if (c < 0x21 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

bool IsValidUserAgent(std::string_view value) {
    if (value.size() > kMaxUserAgentLength) {
        return false;
    }
    return IsValidHeaderValue(value);
}

bool IsValidDnsMode(DnsMode mode) noexcept {
    switch (mode) {
    case DnsMode::System:
    case DnsMode::Doh:
        return true;
    default:
        return false;
    }
}

bool IsValidResolveEntry(std::string_view entry) {
    if (entry.empty() || entry.size() > kMaxResolveEntryLength) {
        return false;
    }
    for (const unsigned char c : entry) {
        // Reject NUL and all control characters so the length-aware entry
        // and the NUL-terminated string handed to curl cannot disagree.
        if (c <= 0x20 || c == 0x7f) {
            return false;
        }
    }
    return true;
}

ErrorCode ValidateDnsStrategy(const DnsStrategy& strategy) {
    if (!IsValidDnsMode(strategy.mode)) {
        return ErrorCode::InvalidDnsMode;
    }
    if (strategy.mode == DnsMode::Doh &&
        !IsValidHttpsUrl(strategy.doh_url)) {
        return ErrorCode::InvalidHardenedDoh;
    }
    if (!strategy.bootstrap_resolve_entry.empty() &&
        !IsValidResolveEntry(std::string_view(
            strategy.bootstrap_resolve_entry.data(),
            strategy.bootstrap_resolve_entry.size()))) {
        return ErrorCode::InvalidDnsMode;
    }
    return ErrorCode::None;
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
