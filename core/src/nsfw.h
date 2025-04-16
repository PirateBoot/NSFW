#pragma once

// DLL Export/Import Macro
#ifdef NSFW_EXPORTS
    #define NSFW_API __declspec(dllexport)
#else
    #define NSFW_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Simple exported function — callable externally
NSFW_API int fnnsfw(void);

// Optional exported init function
NSFW_API void run_payload(void);

#ifdef __cplusplus
}
#endif
