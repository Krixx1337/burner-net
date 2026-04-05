#pragma once

#define BURNERNET_VERSION_MAJOR 1
#define BURNERNET_VERSION_MINOR 2
#define BURNERNET_VERSION_PATCH 0
#define BURNERNET_VERSION_STRING "1.2.0"

namespace burner::net {

inline constexpr int VersionMajor = BURNERNET_VERSION_MAJOR;
inline constexpr int VersionMinor = BURNERNET_VERSION_MINOR;
inline constexpr int VersionPatch = BURNERNET_VERSION_PATCH;
inline constexpr const char* VersionString = BURNERNET_VERSION_STRING;

} // namespace burner::net
