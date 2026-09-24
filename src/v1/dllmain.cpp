#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <winnt.h>

typedef int(*ORIGIN_STRCMP)(const char*, const char*);
ORIGIN_STRCMP original_strcmp = NULL;

int my_strcmp(const char* str1, const char* str2) {
    if (original_strcmp == NULL) {
        original_strcmp = strcmp;
    }
    
    unsigned char encrypted_flag[] = {0xEC, 0x8D, 0xF8, 0xF2, 0x8D, 0xFD, 0xEA, 0xF7, 0xE8, 0x8D, 0xE1, 0xF3, 0xFF, 0xED, 0xEA, 0x8D, 0xEC};
    int flag_len = sizeof(encrypted_flag);

    char real_flag[50] = {0};
    
    for (int i = 0; i < flag_len; i++) {
        real_flag[i] = encrypted_flag[i] ^ 0xBE;
    }
    real_flag[flag_len] = '\0';
    
    if (original_strcmp(str1, real_flag) == 0) {
        printf("You've got it! Real Flag is DH{r3fl3ct1v3_m4st3r}\n");
        printf("Program will exit in 10 seconds~\n");
        Sleep(10000);
        ExitProcess(0);
    }
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



