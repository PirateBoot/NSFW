#pragma once
#include <cstdint>
#include <cstring>
#include <windows.h>
#include <wincrypt.h>

// AES block size (128 bits = 16 bytes)
#define AES_BLOCK_SIZE 16

// AES-XTS context holding tweak and key info
struct xts_aes_context {
    uint8_t key1[32]; // Main key
    uint8_t key2[32]; // Tweak key
    HCRYPTPROV hProv;
    HCRYPTKEY hKeyEnc;
    HCRYPTKEY hKeyTweak;
};

// Sets up keys for AES-XTS mode
inline bool xts_set_key(xts_aes_context* ctx, const uint8_t* key, size_t key_len) {
    if (key_len != 32) return false; // Only support 256-bit key for now

    // Split key into two 128-bit halves
    memcpy(ctx->key1, key, 16);
    memcpy(ctx->key2, key + 16, 16);

    if (!CryptAcquireContextA(&ctx->hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    // Prepare key blobs for both encryption key and tweak key
    struct {
        BLOBHEADER hdr;
        DWORD keyLen;
        uint8_t keyData[16];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_128;
    keyBlob.keyLen = 16;

    memcpy(keyBlob.keyData, ctx->key1, 16);
    if (!CryptImportKey(ctx->hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &ctx->hKeyEnc))
        return false;

    memcpy(keyBlob.keyData, ctx->key2, 16);
    if (!CryptImportKey(ctx->hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &ctx->hKeyTweak))
        return false;

    return true;
}

// Simple ECB block encryption using hKeyEnc
inline void aes_ecb_encrypt(HCRYPTKEY hKey, uint8_t* data) {
    DWORD dwLen = AES_BLOCK_SIZE;
    CryptEncrypt(hKey, 0, TRUE, 0, data, &dwLen, dwLen);
}

// GF(2^128) multiplication by x (XTS tweak evolution)
inline void xts_gf_mul(uint8_t* tweak) {
    uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        uint8_t next = tweak[i];
        tweak[i] = (tweak[i] << 1) | carry;
        carry = (next & 0x80) ? 1 : 0;
    }
    if (carry)
        tweak[15] ^= 0x87;
}

// Encrypt a single block using AES-XTS
inline void xts_encrypt_block(xts_aes_context* ctx, uint8_t* block, uint64_t sector_index) {
    uint8_t tweak[AES_BLOCK_SIZE];
    memset(tweak, 0, AES_BLOCK_SIZE);
    memcpy(tweak, &sector_index, sizeof(sector_index));

    aes_ecb_encrypt(ctx->hKeyTweak, tweak);  // Initial tweak for this sector

    // XOR with tweak
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        block[i] ^= tweak[i];

    aes_ecb_encrypt(ctx->hKeyEnc, block);

    // XOR with tweak again
    for (int i = 0; i < AES_BLOCK_SIZE; ++i)
        block[i] ^= tweak[i];

    xts_gf_mul(tweak);  // Ready tweak for next block (if needed)
}
