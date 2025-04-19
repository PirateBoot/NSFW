
// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the REDWHEEL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// REDWHEEL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef REDWHEEL_EXPORTS
#define REDWHEEL_API __declspec(dllexport)
#else
#define REDWHEEL_API __declspec(dllimport)
#endif

// This class is exported from the dll
class REDWHEEL_API Credwheel {
public:
	Credwheel(void);
	// TODO: add your methods here.
};

extern REDWHEEL_API int nredwheel;

REDWHEEL_API int fnredwheel(void);
