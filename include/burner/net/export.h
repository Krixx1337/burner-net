#pragma once

#if defined(_WIN32)
#if defined(BURNER_SHARED)
#if defined(BURNER_BUILDING_LIBRARY)
#define BURNER_API __declspec(dllexport)
#else
#define BURNER_API __declspec(dllimport)
#endif
#else
#define BURNER_API
#endif
#else
#if defined(BURNER_SHARED)
#define BURNER_API __attribute__((visibility("default")))
#else
#define BURNER_API
#endif
#endif
