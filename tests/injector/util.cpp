#include "util.h"
#include <iostream>

BYTE* util::alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    if (!buffer_size) return NULL;

    BYTE* buf = (BYTE*)VirtualAlloc((LPVOID)desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    return buf;
}

bool util::free_aligned(BYTE* buffer)
{
    if (buffer == nullptr) return true;
    if (!VirtualFree(buffer, 0, MEM_RELEASE)) {
#ifdef _DEBUG
        std::cerr << "Releasing failed" << std::endl;
#endif
        return false;
    }
    return true;
}

BYTE* util::load_file(IN const char *filename, OUT size_t &read_size)
{
    HANDLE file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Could not open file!" << std::endl;
#endif
        return nullptr;
    }
    HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
#ifdef _DEBUG
        std::cerr << "Could not create mapping!" << std::endl;
#endif
        CloseHandle(file);
        return nullptr;
    }
    BYTE *dllRawData = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!dllRawData) {
#ifdef _DEBUG
        std::cerr << "Could not map view of file" << std::endl;
#endif
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    size_t r_size = GetFileSize(file, 0);
    if (read_size != 0 && read_size <= r_size) {
        r_size = read_size;
    }
    if (IsBadReadPtr(dllRawData, r_size)) {
        std::cerr << "[-] Mapping of " << filename << " is invalid!" << std::endl;
        UnmapViewOfFile(dllRawData);
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    BYTE* localCopyAddress = alloc_aligned(r_size, PAGE_READWRITE);
    if (localCopyAddress != nullptr) {
        memcpy(localCopyAddress, dllRawData, r_size);
        read_size = r_size;
    }
    else {
        read_size = 0;
#ifdef _DEBUG
        std::cerr << "Could not allocate memory in the current process" << std::endl;
#endif
    }
    UnmapViewOfFile(dllRawData);
    CloseHandle(mapping);
    CloseHandle(file);
    return localCopyAddress;
}

void util::free_file(BYTE* buffer)
{
    free_aligned(buffer);
}
