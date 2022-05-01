#include <windows.h>
#include <iostream>

#include <peconv.h>

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

	std::cout << "[*] Reading module from: " << in_path << std::endl;
	BYTE *my_exe = peconv::load_file(in_path, exe_size);
	if (!my_exe) {
		std::cerr << "[ERROR] Loading file failed" << std::endl;
		return -1;
	}
	// if the shellcode is a converted PE, check its bitness before running...
	const WORD arch = peconv::get_nt_hdr_architecture(my_exe);
	if (arch) {
#ifdef _WIN64
		if (arch != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			std::cerr << "[ERROR] Bitness mismatch: the given payload is not compatibilie with this loader\n";
			return 0;
		}
#else
		if (arch != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			std::cerr << "[ERROR] Bitness mismatch: the given payload is not compatibilie with this loader\n";
			return 0;
		}
#endif
	}

	BYTE *test_buf = peconv::alloc_aligned(exe_size, PAGE_EXECUTE_READWRITE);
	if (!test_buf) {
		peconv::free_file(my_exe);
		std::cerr << "[ERROR] Allocating buffer failed" << std::endl;
		return -2;
	}

	//copy file content into executable buffer:
	memcpy(test_buf, my_exe, exe_size);

	//free the original buffer:
	peconv::free_file(my_exe);
	my_exe = nullptr;

	std::cout << "[*] Running the shellcode:" << std::endl;
	//run it:
	int (*my_main)() = (int(*)()) ((ULONGLONG)test_buf);
	int ret_val = my_main();
	
	peconv::free_aligned(test_buf, exe_size);
	std::cout << "[+] The shellcode finished with a return value: " << std::hex << ret_val << std::endl;
	return ret_val;
}
