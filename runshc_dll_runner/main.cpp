#include <windows.h>
#include <iostream>

#define LIB_NAME "runshc_dll.dll"
#define FUNC_NAME "run"

int main(int argc, char *argv[])
{
	HMODULE lib = LoadLibraryA("runshc_dll.dll");
	if (!lib) {
		std::cout << LIB_NAME " not found!\n";
		return -1;
	}
	FARPROC run_func = GetProcAddress(lib, "run");
	if (!run_func) {
		std::cout << FUNC_NAME " not found!\n";
		return -1;
	}
	int(*new_main)() = (int(*)())run_func;
	run_func();
	return 0;
}
