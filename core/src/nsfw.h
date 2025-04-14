// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the NSFW_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// NSFW_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef NSFW_EXPORTS
#define NSFW_API __declspec(dllexport)
#else
#define NSFW_API __declspec(dllimport)
#endif

// This class is exported from the dll
class NSFW_API Cnsfw {
public:
	Cnsfw(void);
	// TODO: add your methods here.
};

extern NSFW_API int nnsfw;

NSFW_API int fnnsfw(void);
