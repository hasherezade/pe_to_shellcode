#pragma once

#include <windows.h>


namespace util {

    BYTE* alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base=0);

    bool free_aligned(BYTE* buffer);

    BYTE* load_file(IN const char *filename, OUT size_t &read_size);

    void free_file(BYTE* buffer);
}
