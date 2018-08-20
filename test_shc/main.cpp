#include <windows.h>
#include <iostream>

#include "peconv.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "Test shellcode: loads and deploys the shellcode file" << std::endl;
		std::cout << "Args: <shellcode_file>" << std::endl;
		system("pause");
		return 0;
	}

	size_t exe_size = 0;
	char* in_path = argv[1];

	std::cout << "Reading module from: " << in_path << std::endl;
	BYTE *my_exe = peconv::load_file(in_path, exe_size);
	if (!my_exe) {
		system("pause");
		return -1;
	}

	std::cout << "Test it!" << std::endl;
	BYTE *test_buf = peconv::alloc_aligned(exe_size, PAGE_EXECUTE_READWRITE);
	if (test_buf) {
		memcpy(test_buf, my_exe, exe_size);
		void (*my_main)() = (void (*)()) ((ULONGLONG)test_buf);
		my_main();
	}
	return 0; 
}
