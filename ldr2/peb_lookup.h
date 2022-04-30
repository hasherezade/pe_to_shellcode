#pragma once

#include <windows.h>
#include <winternl.h>

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

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

inline LPVOID get_module_by_name(WCHAR* module_name)
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

        size_t i;
        for (i = 0; i < entry->BaseDllName.Length; i++) {
            // if any of the strings finished:
            if (module_name[i] == 0 || curr_name[i] == 0) {
                break;
            }
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        // both of the strings finished, and so far they were identical:
        if (module_name[i] == 0 && curr_name[i] == 0) {
            return entry->DllBase;
        }
    }

    return nullptr;
}

inline LPVOID get_func_by_name(LPVOID module, char* func_name)
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
        size_t k;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return nullptr;
}
