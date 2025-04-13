#include <windows.h>
#include <iostream>
#include <cstring>

#define MBR_SIZE 512

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

BOOL PetyaReadMemory(PVOID pMemory, INT iMemoryOffset, CHAR* cBuffer) {
    memcpy(cBuffer, (PCHAR)pMemory + iMemoryOffset, 512);
    return TRUE;
}

BOOL PetyaWriteMemory(PVOID pMemory, INT iMemoryOffset, CHAR* cBuffer, DWORD nBytesToWrite) {
    memcpy((PCHAR)pMemory + iMemoryOffset, cBuffer, nBytesToWrite);
    return TRUE;
}

void OverwriteMBR(const unsigned char* bootcode, size_t size) {
    // Simulated MBR write into memory instead of physical device
    BYTE SimulatedMBR[MBR_SIZE];
    memcpy(SimulatedMBR, bootcode, size);

    // Simulate final MBR write with correct boot signature
    SimulatedMBR[510] = 0x55;
    SimulatedMBR[511] = 0xAA;

    // For demo purposes, we simulate an MBR overwrite action
    std::cout << "[+] MBR successfully overwritten (simulated in memory)." << std::endl;
}

int main() {
    std::cout << "[*] Petya-style Bootkit Writer (MBR Overwrite - Fileless Version)\n";

    // Fill bootcode buffer with NOPs if shorter than 512 bytes
    if (sizeof(petyaMBR) < MBR_SIZE)
        memset(petyaMBR + sizeof(petyaMBR), 0x90, MBR_SIZE - sizeof(petyaMBR));

    // Overwrite MBR (simulated in memory)
    OverwriteMBR(petyaMBR, MBR_SIZE);

    return 0;
}
