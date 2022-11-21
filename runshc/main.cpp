#include <windows.h>
#include <iostream>

#include <peconv.h>
#include "..\loader_v2\peloader.h"

typedef struct {
	BYTE* my_exe;
	size_t exe_size;
	bool is_run;
} t_module_params;

bool load_and_run(t_module_params& args)
{
	BYTE* test_buf = peconv::alloc_aligned(args.exe_size, PAGE_EXECUTE_READWRITE);
	if (!test_buf) {
		std::cerr << "[ERROR] Allocating buffer failed" << std::endl;
		return false;
	}

	//copy file content into executable buffer:
	memcpy(test_buf, args.my_exe, args.exe_size);

	//free the original buffer:
	peconv::free_file(args.my_exe);
	args.my_exe = nullptr;

	std::cout << "[*] Running the shellcode [" << std::hex << (ULONG_PTR) test_buf << " - " << (ULONG_PTR)(test_buf + args.exe_size) << "]" << std::endl;
	//run it:
	int (*my_main)() = (int(*)()) ((ULONGLONG)test_buf);
	int ret_val = my_main();
	args.is_run = true;
	min_hdr_t *my_hdr = (min_hdr_t*)test_buf;
	if (my_hdr->load_status == LDS_ATTACHED) {
		//run again to unload DLL:
		std::cout << "[*] Running again to unload the DLL...\n";
		my_main();
		std::cout << "[*] Load status: " << (int)my_hdr->load_status << "\n";
	}
	peconv::free_aligned(test_buf, args.exe_size);
	std::cout << "[+] The shellcode finished with a return value: " << std::hex << ret_val << std::endl;
	return true;
}


DWORD WINAPI mod_runner(LPVOID lpParam)
{
	t_module_params* args = static_cast<t_module_params*>(lpParam);
	if (!args) {
		return ERROR_BAD_ARGUMENTS;
	}
	args->is_run = false;
	load_and_run(*args);
	return S_OK;
}

bool run_in_new_thread(t_module_params &args)
{
	std::cout << ">>> Creating a new thread...\n";
	HANDLE hThead = CreateThread(
		NULL,                   // default security attributes
		0,                      // use default stack size  
		mod_runner,       // thread function name
		&args,          // argument to thread function 
		0,                      // use default creation flags 
		0);   // returns the thread identifier 

	if (!hThead) {
		std::cerr << "Failed to created the thread!\n";
		return false;
	}
	DWORD wait_result = WaitForSingleObject(hThead, INFINITE);
	return (args.is_run);
}

bool run_in_curr_thread(t_module_params &args)
{
	std::cout << ">>> Running in a current thread...\n";
	load_and_run(args);
	return (args.is_run);
}

#define NEW_THREAD

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

	t_module_params args = { 0 };
	args.my_exe = my_exe;
	args.exe_size = exe_size;
	args.is_run = false;

#ifdef NEW_THREAD
	bool res = run_in_new_thread(args);
#else
	bool res = run_in_curr_thread(args);
#endif
	if (args.my_exe) {
		peconv::free_file(args.my_exe);
		args.my_exe = nullptr;
		my_exe = nullptr;
	}
	std::cout << ">>> FINISHED.\n";
	return 0;
}
