#include "pch.h"
#include <Windows.h>
#include <lm.h>
#include <iostream>
#include <fstream>

#pragma comment(lib, "netapi32.lib")

wchar_t username[256] = L"adm1n";
wchar_t password[256] = L"P@ssw0rd";

// Simulated DLL Injection (no real process manipulation)
BOOL InjectDLL(HANDLE hProcess, const char* dllPath) {
    // Simulate memory allocation for the DLL path
    LPVOID pRemotePath = VirtualAlloc(NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemotePath) return FALSE;

    // Simulate writing the DLL path into the allocated memory
    memcpy(pRemotePath, dllPath, strlen(dllPath) + 1);

    // Simulate loading the library without real injection
    std::wcout << L"Simulated DLL injection to: " << dllPath << std::endl;

    // Clean up simulated memory
    VirtualFree(pRemotePath, 0, MEM_RELEASE);

    return TRUE;
}

// Simulate user creation (no real user added)
BOOL CreateUser() {
    // Simulate creating a user in memory (not really adding it)
    USER_INFO_1 user;
    memset(&user, 0, sizeof(USER_INFO_1));
    user.usri1_name = username;
    user.usri1_password = password;
    user.usri1_priv = USER_PRIV_USER;
    user.usri1_flags = UF_DONT_EXPIRE_PASSWD;

    // Instead of creating the user, just output a message
    std::wcout << L"Simulated user created: " << username << std::endl;

    return TRUE;
}

// Simulate adding the user to the Administrators group (no real changes)
BOOL AddUserToAdminGroup() {
    LOCALGROUP_MEMBERS_INFO_3 members;
    members.lgrmi3_domainandname = username;

    // Output simulation message
    std::wcout << L"Simulated addition of " << username << L" to the Administrators group." << std::endl;

    return TRUE;
}

// Simulate the DLL Main Entry Point (no real system changes)
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Simulate user creation
        CreateUser();

        // Simulate adding the user to the Administrators group
        AddUserToAdminGroup();

        // Simulate DLL injection (no actual injection)
        DWORD processId = 1234; // Replace with the target process ID for simulation
        std::wcout << L"Simulating DLL injection into process ID: " << processId << std::endl;
        InjectDLL(NULL, "C:\\Path\\To\\NSFW.dll"); // No real injection, just a message

        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
