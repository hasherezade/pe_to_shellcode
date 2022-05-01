#include <Windows.h>
#include "peb_lookup.h"

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

#ifdef _WIN64
#define RELOC_FIELD RELOC_64BIT_FIELD
typedef ULONG_PTR FIELD_PTR;
#else
#define RELOC_FIELD RELOC_32BIT_FIELD
typedef  DWORD_PTR FIELD_PTR;
#endif

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

typedef struct
{
    decltype(&LoadLibraryA) _LoadLibraryA;
    decltype(&GetProcAddress) _GetProcAddress;
} t_mini_iat;

bool init_iat(t_mini_iat &iat)
{
    LPVOID base = get_module_by_name((const LPWSTR)L"kernel32.dll");
    if (!base) {
        return false;
    }

    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return false;
    }
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return false;
    }

    iat._LoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(load_lib);
    iat._GetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(get_proc);
    return true;
}


bool apply_reloc(ULONG_PTR relocField, ULONG_PTR oldBase, ULONG_PTR newBase)
{
#ifdef _WIN64
        ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)relocField);
        ULONGLONG rva = (*relocateAddr) - oldBase;
        (*relocateAddr) = rva + newBase;
#else
        DWORD* relocateAddr = (DWORD*)((ULONG_PTR)relocField);
        ULONGLONG rva = ULONGLONG(*relocateAddr) - oldBase;
        (*relocateAddr) = static_cast<DWORD>(rva + newBase);
#endif
    return true;
}

bool process_reloc_block(BASE_RELOCATION_ENTRY* block, SIZE_T entriesNum, DWORD page, PVOID modulePtr, ULONG_PTR oldBase)
{
    if (entriesNum == 0) {
        return true; // nothing to process
    }
    BASE_RELOCATION_ENTRY* entry = block;
    SIZE_T i = 0;
    for (i = 0; i < entriesNum; i++) {
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        if (type == 0) {
            break;
        }
        if (type != RELOC_FIELD) {
            return false;
        }
        
        DWORD reloc_field_rva = page + offset;
        ULONG_PTR reloc_field = (ULONG_PTR)modulePtr + reloc_field_rva;
        apply_reloc(reloc_field, oldBase, (ULONG_PTR)modulePtr);
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
    }
    return true;
}

bool apply_relocations(IMAGE_DATA_DIRECTORY& relocDir, BYTE* modulePtr, ULONG_PTR oldBase)
{
    DWORD maxSize = relocDir.Size;
    DWORD relocAddr = relocDir.VirtualAddress;

    IMAGE_BASE_RELOCATION* reloc = NULL;
    DWORD parsedSize = 0;
    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR)modulePtr);
        if (reloc->SizeOfBlock == 0) {
            break;
        }

        const size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
        const DWORD page = reloc->VirtualAddress;
        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
        if (!process_reloc_block(block, entriesNum, page, modulePtr, oldBase)) {
            return false;
        }
        parsedSize += reloc->SizeOfBlock;
    }
    return true;
}

bool load_imports(t_mini_iat iat, IMAGE_DATA_DIRECTORY importsDirectory, BYTE* image)
{
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (ULONG_PTR)image);

    while (importDescriptor->Name != NULL)
    {
        LPCSTR libraryName = (LPCSTR)((ULONG_PTR)importDescriptor->Name + (ULONG_PTR)image);
        HMODULE library = iat._LoadLibraryA(libraryName);
        if (!library) return false;

        PIMAGE_THUNK_DATA thunk = NULL;
        thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)image + importDescriptor->FirstThunk);

        while (thunk->u1.AddressOfData != NULL)
        {
            FIELD_PTR functionAddress = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                functionAddress = (FIELD_PTR)iat._GetProcAddress(library, functionOrdinal);
            }
            else {
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)image + thunk->u1.AddressOfData);
                functionAddress = (FIELD_PTR)iat._GetProcAddress(library, functionName->Name);
            }
            if (!functionAddress) return false;

            thunk->u1.Function = functionAddress;
            ++thunk;
        }
        importDescriptor++;
    }
    return (importDescriptor > 0);
}

int __stdcall main(void *module_base)
{
    t_mini_iat iat;
    if (!init_iat(iat)) {
        return (-1);
    }
    IMAGE_DOS_HEADER* mz = (IMAGE_DOS_HEADER*)module_base;
    IMAGE_NT_HEADERS* pe = (IMAGE_NT_HEADERS*)(mz->e_lfanew + (ULONG_PTR)module_base);
    if (pe->Signature != 0x4550) {
        return (-2);
    }
    IMAGE_DATA_DIRECTORY &relocDir = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir.VirtualAddress) {
        return (-3);
    }
    const ULONG_PTR oldBase = pe->OptionalHeader.ImageBase;
    if (!apply_relocations(relocDir, (BYTE*)module_base, oldBase)) {
        return (-4);
    }
    IMAGE_DATA_DIRECTORY& importDir = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress) {
        if (!load_imports(iat, importDir, (BYTE*)module_base)) {
            return (-5);
        }
    }

    const DWORD ep_rva = pe->OptionalHeader.AddressOfEntryPoint;
    const ULONG_PTR ep_va = (ULONG_PTR)module_base + ep_rva;

    if (pe->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        BOOL (WINAPI *my_DllMain)(HINSTANCE, DWORD, LPVOID) 
            = (BOOL(WINAPI *)(HINSTANCE, DWORD, LPVOID)) (ep_va);
        return my_DllMain((HINSTANCE)module_base, DLL_PROCESS_ATTACH, 0);
    }
    int(*my_main)() = (int(*)()) (ep_va);
    return my_main();
}
