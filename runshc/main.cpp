#include <windows.h>
#include <iostream>

#include "peconv.h"

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "~ runshc ~\n"
			<< "Run shellcode: loads and deploys shellcode file.\n";
#ifdef _WIN64
		std::cout << "For 64-bit shellcodes.\n";
#else
		std::cout << "For 32-bit shellcodes.\n";
#endif
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
	if (!test_buf) {
		peconv::free_file(my_exe);
		system("pause");
		return -2;
	}
	//copy file content into executable buffer:
	memcpy(test_buf, my_exe, exe_size);

	//free the original buffer:
	peconv::free_file(my_exe);
	my_exe = nullptr;

	//run it:
	int (*my_main)() = (int(*)()) ((ULONGLONG)test_buf);
	int ret_val = my_main();
	
	peconv::free_aligned(test_buf, exe_size);
	return ret_val;
}
