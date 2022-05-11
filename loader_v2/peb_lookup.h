#pragma once

#include <windows.h>
#include <winternl.h>

// enhanced version of LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY1 {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY1, * PLDR_DATA_TABLE_ENTRY1;


template<typename CHAR_TYPE>
inline DWORD calc_checksum(CHAR_TYPE* curr_name, bool case_sensitive)
{
    DWORD crc = 0xFFFFFFFF;
    size_t k;
    for (k = 0; curr_name[k] != 0; k++) {
        CHAR_TYPE ch = curr_name[k];
        if (!case_sensitive) {
            ch = (ch <= 'Z' && ch >= 'A') ? (ch - 'A') + 'a' : ch;
        }
        for (size_t j = 0; j < 8; j++) {
            DWORD b = (ch ^ crc) & 1;
            crc >>= 1;
            if (b) crc = crc ^ 0xEDB88320;
            ch >>= 1;
        }
    }
    return ~crc;
}

inline LPVOID get_module_by_checksum(DWORD checksum)
{
    PEB *peb;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PEB_LDR_DATA *ldr = peb->Ldr;

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    for(LIST_ENTRY *current = head->Flink; current != head; current = current->Flink){
        LDR_DATA_TABLE_ENTRY1* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY1, InMemoryOrderLinks);
        if (!entry || !entry->DllBase) break;

        WCHAR* curr_name = entry->BaseDllName.Buffer;
        if (!curr_name) continue;

        DWORD curr_crc = calc_checksum(curr_name, false);
        if (curr_crc == checksum) {
            //found
            return entry->DllBase;
        }
    }
    return nullptr;
}

inline LPVOID get_func_by_checksum(LPVOID module, DWORD checksum)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!exportsDir->VirtualAddress) {
        return nullptr;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        DWORD curr_crc = calc_checksum(curr_name, true);
        if (curr_crc == checksum) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return nullptr;
}
