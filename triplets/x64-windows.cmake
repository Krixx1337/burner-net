# vcpkg's x64-windows, except nghttp2 links statically into libcurl.dll. The
# http2 feature then adds no DLL: the runtime stays zlib1, libcrypto-3-x64,
# libssl-3-x64 and libcurl, and BURNERNET_HARDEN_IMPORTS rejects any other DLL
# in the runtime folder.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
if(PORT STREQUAL "nghttp2")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
