# vcpkg's x86-windows, except nghttp2 links statically into libcurl.dll, as in
# x64-windows.cmake: the http2 feature adds no DLL to the x86 runtime either.
set(VCPKG_TARGET_ARCHITECTURE x86)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
if(PORT STREQUAL "nghttp2")
    set(VCPKG_LIBRARY_LINKAGE static)
endif()
