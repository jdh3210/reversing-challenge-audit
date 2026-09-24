#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>
// REV-01: flag_gen.py가 생성하는 enc_flag / FLAG_HASH
#include "flag_blob.h"

// REV-01: flag_gen.py의 fnv1a64 / keystream과 바이트 단위로 동일해야 한다
#define FNV64_OFFSET 0xCBF29CE484222325ULL
#define FNV64_PRIME  0x100000001B3ULL

static unsigned long long fnv1a64(const unsigned char* data, size_t len) {
    unsigned long long h = FNV64_OFFSET;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= FNV64_PRIME;       // unsigned long long이므로 2^64로 자동 랩어라운드
    }
    return h;
}

static void keystream(unsigned long long seed, unsigned char* out, size_t len) {
    unsigned long long h = seed;
    size_t produced = 0;
    while (produced < len) {
        h *= FNV64_PRIME;
        h ^= (h >> 29);
        for (int i = 0; i < 8 && produced < len; i++, produced++) {
            out[produced] = (unsigned char)((h >> (8 * i)) & 0xFF);
        }
    }
}

typedef int(*ORIGIN_STRCMP)(const char*, const char*);
ORIGIN_STRCMP original_strcmp = NULL;

int my_strcmp(const char* str1, const char* str2) {
    if (original_strcmp == NULL) {
        original_strcmp = strcmp;
    }

    // REV-02: 미끼 비교를 후킹 지점에서 실패시켜 가짜 플래그 경로를 차단한다
    if (original_strcmp(str2, "EASY_REVERSING") == 0) {
        return 1;
    }

    // REV-01: 평문 플래그 대신 사용자 입력에서 유도한 키스트림으로만 복호화한다
    size_t in_len = 0;
    while (str1[in_len] != '\0') in_len++;

    unsigned long long seed = fnv1a64((const unsigned char*)str1, in_len);

    unsigned char ks[sizeof(enc_flag)];
    unsigned char out[sizeof(enc_flag) + 1] = { 0 };

    keystream(seed, ks, sizeof(enc_flag));
    for (size_t i = 0; i < sizeof(enc_flag); i++) {
        out[i] = enc_flag[i] ^ ks[i];
    }

    // REV-01: 입력이 아니라 '복호화 결과'를 검증한다
    if (fnv1a64(out, sizeof(enc_flag)) == FLAG_HASH) {
        printf("You've got it! %s\n", (char*)out);
        printf("Program will exit in 10 seconds~\n");
        Sleep(10000);
        ExitProcess(0);
    }

    // REV-01: 실패 경로에서는 복호화 버퍼를 즉시 파기한다
    SecureZeroMemory(out, sizeof(out));
    SecureZeroMemory(ks, sizeof(ks));

    return original_strcmp(str1, str2);
}

void hook_IAT() {
    HMODULE base_address = GetModuleHandle(NULL);

    if (base_address == NULL) {
        //printf("Failed to get module handle.\n");
        return;
    }

    //printf("Process Base: 0x%p\n", base_address);

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_address;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        //printf("Invalid DOS header...\n");
            return;
    }
    //printf("Dos Header OK~\n");

    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((BYTE*)base_address + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        //printf("Invalid NT header...\n");
            return;
    }
    //printf("NT Header is all set and ready~\n");

    PIMAGE_DATA_DIRECTORY import_directory = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_directory->Size != 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)base_address + import_directory->VirtualAddress);

        while (import_desc->Name != 0) {
            char* current_dll = (char*)base_address + import_desc->Name;
            //printf("Current DLL: %s\n", current_dll);

            PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)base_address + import_desc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)base_address + import_desc->FirstThunk);

            while (original_first_thunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                    original_first_thunk++;
                    first_thunk++;
                    continue;
                }

                PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)base_address + original_first_thunk->u1.AddressOfData);
                if (strcmp((char*)import_by_name->Name, "strcmp") == 0) {
                    //printf("Found strcmp!\n");

                    DWORD oldProtect;
                    VirtualProtect(first_thunk, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect);

                    original_strcmp = (ORIGIN_STRCMP)first_thunk->u1.Function;
                    first_thunk->u1.Function = (ULONG_PTR)my_strcmp;

                    VirtualProtect(first_thunk, sizeof(ULONG_PTR), oldProtect, &oldProtect);

                    //printf("Hooking strcmp is successful!\n");
                    return;
                }
                original_first_thunk++;
                first_thunk++;
            }
            import_desc++;
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        hook_IAT();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
