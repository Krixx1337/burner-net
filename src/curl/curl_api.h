#pragma once

#include "burner/net/detail/pointer_mangling.h"

#include <curl/curl.h>

namespace burner::net {

using CurlEasyInitFn = CURL* (*)();
using CurlEasyCleanupFn = void (*)(CURL*);
using CurlEasyResetFn = void (*)(CURL*);
using CurlEasySetoptFn = CURLcode (*)(CURL*, CURLoption, ...);
using CurlEasyPerformFn = CURLcode (*)(CURL*);
using CurlEasyGetinfoFn = CURLcode (*)(CURL*, CURLINFO, ...);
using CurlSlistAppendFn = curl_slist* (*)(curl_slist*, const char*);
using CurlSlistFreeAllFn = void (*)(curl_slist*);
using CurlEasyStrerrorFn = const char* (*)(CURLcode);

// Callback types required by curl_global_init_mem.
using CurlMallocCallback  = void* (*)(size_t size);
using CurlFreeCallback    = void  (*)(void* ptr);
using CurlReallocCallback = void* (*)(void* ptr, size_t size);
using CurlStrdupCallback  = char* (*)(const char* str);
using CurlCallocCallback  = void* (*)(size_t nmemb, size_t size);

using CurlGlobalInitMemFn = CURLcode (*)(long flags,
    CurlMallocCallback m,
    CurlFreeCallback   f,
    CurlReallocCallback r,
    CurlStrdupCallback  s,
    CurlCallocCallback  c);

struct CurlApi {
    EncodedPointer<CurlEasyInitFn> easy_init = nullptr;
    EncodedPointer<CurlEasyCleanupFn> easy_cleanup = nullptr;
    EncodedPointer<CurlEasyResetFn> easy_reset = nullptr;
    EncodedPointer<CurlEasySetoptFn> easy_setopt = nullptr;
    EncodedPointer<CurlEasyPerformFn> easy_perform = nullptr;
    EncodedPointer<CurlEasyGetinfoFn> easy_getinfo = nullptr;
    EncodedPointer<CurlSlistAppendFn> slist_append = nullptr;
    EncodedPointer<CurlSlistFreeAllFn> slist_free_all = nullptr;
    EncodedPointer<CurlEasyStrerrorFn> easy_strerror = nullptr;
    EncodedPointer<CurlGlobalInitMemFn> global_init_mem = nullptr;
};

} // namespace burner::net
