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
};

} // namespace burner::net
