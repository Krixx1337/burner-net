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

    for (unsigned char c : name) {
        if (std::isalnum(c)) {
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
    return !ContainsCrlf(value);
}

} // namespace burner::net::internal
