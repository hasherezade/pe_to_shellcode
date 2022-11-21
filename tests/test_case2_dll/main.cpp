#include <Windows.h>
#include <iostream>

#define TEST_NAME "Test Case 2"
inline DWORD rotl32a(DWORD x, DWORD n)
{
    return (x << n) | (x >> (32 - n));
}

inline char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        c = c - 'A' + 'a';
    }
    return c;
}

DWORD calc_checksum(BYTE *str, size_t buf_size, bool enable_tolower)
{
    if (str == NULL) return 0;

    DWORD checksum = 0;
    for (size_t i = 0; i < buf_size; i++) {
        checksum = rotl32a(checksum, 7);
        char c = str[i];
        if (enable_tolower) {
            c = to_lower(c);
        }
        checksum ^= c;
    }
    return checksum;
}

int test_checksum1()
{
    char test1[] = "this is a test!";
    DWORD checks = calc_checksum((BYTE*)test1, strlen(test1), true);
    std::cout << "Checks 1: " << std::hex << checks << std::endl;
    return checks;
}

BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    std::cout << __FUNCTION__ << std::endl;
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        std::cout << TEST_NAME << " DLL loaded\n";
        test_checksum1();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        std::cout << TEST_NAME << " DLL unloaded\n";
        break;
    }
    return TRUE;
}
