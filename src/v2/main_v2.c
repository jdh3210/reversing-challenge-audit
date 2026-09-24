#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <string.h>
#include "shellcode.h"

#ifndef _CUSTOM_STRUCTURES_
#define _CUSTOM_STRUCTURES_

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#endif

void* my_memcpy(void* dest, const void* src, size_t count) {
    char* pDest = (char*)dest;
    char* pSrc = (char*)src;
    void* original_dest = dest;

    for (size_t i = 0; i < count; i++) {
        *pDest = *pSrc;
        pDest++;
        pSrc++;
    }
    return original_dest;
}

void* my_memset(void* dest, int val, size_t count) {
    char* pDest = (char*)dest;
    char value = (char)val;
    void* original_dest = dest;

    for (size_t i = 0; i < count; i++) {
        *pDest = value;
        pDest++;
    }
    return original_dest;
}

BOOL my_wstricmp(const wchar_t* str1, const wchar_t* str2) {
    while (*str1 != L'\0' && *str2 != L'\0') {
        wchar_t c1 = *str1;
        wchar_t c2 = *str2;

        if (c1 >= L'a' && c1 <= L'z') {
            c1 -= 32;
        }
        if (c2 >= L'a' && c2 <= L'z') {
            c2 -= 32;
        }

        if (c1 != c2) {
            return FALSE;
        }

        str1++;
        str2++;
    }

    if (*str1 != L'\0' || *str2 != L'\0') {
        return FALSE;
    }
    return TRUE;
}

BOOL my_stricmp(const char* str1, const char* str2) {
    while (*str1 != '\0' && *str2 != '\0') {
        char c1 = *str1;
        char c2 = *str2;

        if (c1 >= 'a' && c1 <= 'z') {
            c1 -= 32;
        }
        if (c2 >= 'a' && c2 <= 'z') {
            c2 -= 32;
        }

        if (c1 != c2) {
            return FALSE;
        }

        str1++;
        str2++;
    }

    if (*str1 != '\0' || *str2 != '\0') {
        return FALSE;
    }
    return TRUE;
}

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);

// IDA: sub_140001000
ULONG_PTR ReflectiveLoader(LPVOID dllBuffer) {
    uintptr_t library_address = (uintptr_t)dllBuffer;

    char load_lib_str[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0 };
    char get_proc_address_str[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char virtual_alloc_str[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0 };
    wchar_t kernel32_str[] = { 'K','E','R','N','E','L','3','2','.','D','L','L', 0 };

    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr_entry = peb->Ldr;
    PLIST_ENTRY list_head = &(ldr_entry->InLoadOrderModuleList);
    PLIST_ENTRY current_entry = list_head->Flink;
    PVOID k32_base = NULL;

    while (current_entry != list_head) {
        PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (my_wstricmp(module_entry->BaseDllName.Buffer, kernel32_str)) {
            k32_base = module_entry->DllBase;
            break;
        }
        current_entry = current_entry->Flink;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)k32_base;
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)k32_base + dos_header->e_lfanew);
    DWORD export_RVA = nt_header->OptionalHeader.DataDirectory[0].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)k32_base + export_RVA);

    DWORD names_RVA = export_dir->AddressOfNames;
    DWORD* pNames = (DWORD*)((BYTE*)k32_base + names_RVA);
    DWORD ordinals_RVA = export_dir->AddressOfNameOrdinals;
    WORD* pOrdinals = (WORD*)((BYTE*)k32_base + ordinals_RVA);
    DWORD functions_RVA = export_dir->AddressOfFunctions;
    DWORD* pFunctions = (DWORD*)((BYTE*)k32_base + functions_RVA);
    DWORD number = (DWORD)export_dir->NumberOfNames;

    PVOID load_lib_base = NULL;
    PVOID get_proc_address_base = NULL;
    PVOID virtual_alloc_base = NULL;

    int found_count = 0;

    for (DWORD i = 0; i < number; i++) {
        if (found_count >= 3) {
            break;
        }

        CHAR* current_name = (CHAR*)k32_base + pNames[i];
        if (my_stricmp(current_name, load_lib_str)) {
            DWORD load_lib_RVA = (DWORD)pFunctions[pOrdinals[i]];
            load_lib_base = ((BYTE*)k32_base + load_lib_RVA);
            found_count++;
            continue;
        }
        else if (my_stricmp(current_name, get_proc_address_str)) {
            DWORD get_proc_address_RVA = (DWORD)pFunctions[pOrdinals[i]];
            get_proc_address_base = ((BYTE*)k32_base + get_proc_address_RVA);
            found_count++;
            continue;
        }
        else if (my_stricmp(current_name, virtual_alloc_str)) {
            DWORD virtual_alloc_RVA = (DWORD)pFunctions[pOrdinals[i]];
            virtual_alloc_base = ((BYTE*)k32_base + virtual_alloc_RVA);
            found_count++;
            continue;
        }
    }

    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)load_lib_base;
    GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)get_proc_address_base;
    VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)virtual_alloc_base;

    PIMAGE_DOS_HEADER dll_dos_header = (PIMAGE_DOS_HEADER)library_address;
    PIMAGE_NT_HEADERS dll_nt_header = (PIMAGE_NT_HEADERS)(library_address + dll_dos_header->e_lfanew);

    DWORD image_size = dll_nt_header->OptionalHeader.SizeOfImage;
    LPVOID new_base = pVirtualAlloc(NULL, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    DWORD header_size = dll_nt_header->OptionalHeader.SizeOfHeaders;
    my_memcpy(new_base, (void*)library_address, header_size);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(dll_nt_header);
    DWORD section_number = (DWORD)dll_nt_header->FileHeader.NumberOfSections;

    for (DWORD i = 0; i < section_number; i++) {
        DWORD section_RVA = section[i].VirtualAddress;
        DWORD file_offset = section[i].PointerToRawData;
        DWORD size = section[i].SizeOfRawData;

        void* dest = (char*)new_base + section_RVA;
        void* src = (char*)library_address + file_offset;
        my_memcpy(dest, src, size);
    }

    PIMAGE_DATA_DIRECTORY import_directory = &dll_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_directory->Size != 0) {
        PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((char*)new_base + import_directory->VirtualAddress);

        while (import_desc->Name != 0) {
            char* current_dll = (char*)new_base + import_desc->Name;
            HMODULE hDll = pLoadLibraryA(current_dll);

            PIMAGE_THUNK_DATA original_first_thunk = (PIMAGE_THUNK_DATA)((char*)new_base + import_desc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA first_thunk = (PIMAGE_THUNK_DATA)((char*)new_base + import_desc->FirstThunk);

            while (original_first_thunk->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(original_first_thunk->u1.Ordinal)) {
                    ULONG_PTR func_address = (ULONG_PTR)pGetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(original_first_thunk->u1.Ordinal));
                    first_thunk->u1.Function = func_address;
                }
                else {
                    PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((char*)new_base + original_first_thunk->u1.AddressOfData);
                    ULONG_PTR func_address = (ULONG_PTR)pGetProcAddress(hDll, (LPCSTR)import_by_name->Name);
                    first_thunk->u1.Function = func_address;
                }

                original_first_thunk++;
                first_thunk++;
            }
            import_desc++;
        }
    }

    ULONG_PTR delta = (ULONG_PTR)new_base - dll_nt_header->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY reloc_dir = &dll_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (reloc_dir->Size > 0) {
        PIMAGE_BASE_RELOCATION reloc_block = (PIMAGE_BASE_RELOCATION)((char*)new_base + reloc_dir->VirtualAddress);

        while (reloc_block->SizeOfBlock > 0) {
            ULONG_PTR block_page_address = (ULONG_PTR)new_base + reloc_block->VirtualAddress;
            DWORD entry_count = (reloc_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entry_list = (WORD*)((char*)reloc_block + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < entry_count; i++) {
                WORD entry = entry_list[i];
                WORD type = entry >> 12;
                WORD offset = entry & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR* patch_address = (ULONG_PTR*)(block_page_address + offset);
                    *patch_address += delta;
                }
            }
            reloc_block = (PIMAGE_BASE_RELOCATION)((char*)reloc_block + reloc_block->SizeOfBlock);
        }
    }

    ULONG_PTR entry_point_RVA = dll_nt_header->OptionalHeader.AddressOfEntryPoint;
    ULONG_PTR entry_point = (ULONG_PTR)new_base + entry_point_RVA;

    typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
    DLLMAIN pDllMain = (DLLMAIN)entry_point;

    pDllMain((HINSTANCE)new_base, DLL_PROCESS_ATTACH, NULL);

    return (ULONG_PTR)new_base;
}

// IDA: sub_140002000
void NTAPI TlsCallback(PVOID hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        //printf("I am TLS Callback! You have to go through me before going through main :)\n");

        PPEB peb = (PPEB)__readgsqword(0x60);
        BYTE check_debugging = peb->BeingDebugged;
        BYTE key1 = 0x77 * (1 - check_debugging);

        BYTE key2 = (shellcode_len >> 8) & 0xFF;

        char* team_name = "TEAMH4C";
        BYTE total = 0;
        for (int i = 0; team_name[i] != '\0'; i++) {
            total = total + team_name[i];
        }
        BYTE key3 = total & 0xFF;

        BYTE final_key = key1 ^ key2 ^ key3;

        //printf("Here's key1 from the debugging status: 0x%02X\n", key1);
        //printf("Here's key2 from the file length: 0x%02X\n", key2);
        //printf("Here's key3 from the team name: 0x%02X\n", key3);
        //printf("You gotta go through me first! Here's final key: 0x%02X\n", final_key);

        //printf("Let's start to decrypt shellcode :) \n");

        DWORD oldProtect;
        VirtualProtect(shellcode, shellcode_len, PAGE_EXECUTE_READWRITE, &oldProtect);

        for (unsigned int i = 0; i < shellcode_len; i++) {
            shellcode[i] ^= final_key;
        }

        //printf("Decryption all wrapped up - no problems here :) \n");

        // REV-04: MZ 매직 검사 제거 (브루트포스 정답 판별기로 악용되던 오라클)
        //printf("Alright, loading up Real.dll into memory...\n");
        ReflectiveLoader(shellcode);
        //printf("Real.dll is loaded and IAT Hooking is all hooked up~!\n");

    }
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_tls_callback")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_p_tls_callback")
#endif

#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK p_tls_callback = TlsCallback;

int main() {
    printf("Load start~\n");
    while (1) {
        char input[100];
        printf("Enter password: ");
        scanf_s("%s", input, (unsigned)_countof(input));

        printf("You entered: %s\n", input);

        if (strcmp(input, "EASY_REVERSING") == 0) {
            printf("Wow, Are you genius? flag is DH{too_easy_password}\n");
            continue;
        }

        int result = strcmp(input, "NEVER_MATCH_THIS");

        if (result != 0) {
            printf("Wrong~\n");
        }

        printf("\n");
    }

    return 0;
}
