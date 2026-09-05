#pragma once

#include <cstddef>
#include <string_view>

#include "burner/net/error.h"
#include "burner/net/http.h"

namespace burner::net::internal {

// Maximum accepted User-Agent length. Bounds the bytes serialized into the
// outgoing `User-Agent:` header line; longer values are rejected, never
// silently truncated.
inline constexpr std::size_t kMaxUserAgentLength = 512;

// Maximum accepted CURLOPT_RESOLVE entry length ("host:port:address").
inline constexpr std::size_t kMaxResolveEntryLength = 512;

bool IsValidHeaderName(std::string_view name);
bool IsValidHeaderValue(std::string_view value);
bool IsValidBearerToken(std::string_view token);
bool IsValidHttpsUrl(std::string_view url);

// User-Agent values bypass ordinary header validation on their way to
// CURLOPT_USERAGENT, so they need the same control-character rejection here:
// CR, LF, NUL, and other disallowed controls are rejected, plus a length
// bound. Empty means "no User-Agent configured" and is accepted.
bool IsValidUserAgent(std::string_view value);

// Exhaustive DnsMode check. Unknown numeric values (e.g. from a raw cast or
// deserialized configuration) are rejected rather than treated as DoH or
// system DNS by accident.
bool IsValidDnsMode(DnsMode mode) noexcept;

// CURLOPT_RESOLVE entries cross a C API boundary like URLs do: reject NUL
// and control characters so the validated entry and the transmitted C string
// cannot disagree. Empty means "no entry" and is rejected here; callers skip
// empty entries before validating.
bool IsValidResolveEntry(std::string_view entry);

// One shared DNS strategy validator for the builder path (ClientBuilder) and
// the raw request path (send time). Returns ErrorCode::None when the strategy
// is well formed.
ErrorCode ValidateDnsStrategy(const DnsStrategy& strategy);

} // namespace burner::net::internal
