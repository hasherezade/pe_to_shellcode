/*
	based on the code by: july0426 (https://github.com/july0426)
	modified by: hasherezade (https://github.com/hasherezade)
*/

//#include "pch.h"
#include <fcntl.h>

#include <iostream>
#include <cstdio>
#include <string>
#include <cstring>
#include <atlstr.h>
#include <tchar.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <peconv.h>
#include<stdio.h>
#include <io.h>
#include<vector>
#include <direct.h>

using namespace std;

//#define INFO //pop up message boxes

#define MY_API __declspec(dllexport)  __cdecl

void getFiles(string path, string path2, vector<string>& files)
{
	intptr_t   hFile = 0;
	struct _finddata_t fileinfo;
	string p, p2;
	if ((hFile = _findfirst(p.assign(path).append(path2).append("*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
					getFiles(p.assign(path).append("\\"), p2.assign(fileinfo.name).append("\\"), files);
			}
			else
			{
				files.push_back(p.assign(path2).append(fileinfo.name));
				//files.push_back(p.assign(fileinfo.name) );   
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}

std::string Find_exename() {
	LPTSTR pCommandLine;

	pCommandLine = GetCommandLine();
#ifdef INFO
	MessageBox(0, pCommandLine, L"Commandline", MB_OK);
#endif
	int nArgs;
	LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (!szArglist)
	{
#ifdef INFO
		MessageBoxW(0, L"CommandLineToArgvW failed\n", L"Commandline", MB_OK);
#endif
		return 0;
	}
	size_t last_arg = nArgs - 1;
	if (last_arg == 0) {
		// the first argument is the original EXE, so skip it
		std::cerr << "Missing argument: <shellcode module>\n";
		return "";
	}
	std::wstring ws = szArglist[last_arg];
	const std::string load_name(ws.begin(), ws.end());
	return load_name;
}

int Load_ShellCode() {
	string load_name = Find_exename();
	if (load_name.length() == 0) {
		return -1;
	}
	char* in_path = (char*)load_name.data();
#ifdef INFO
	MessageBoxA(0, in_path, "Found", MB_OK);
#endif
	std::cout << "[*] Reading module from: " << in_path << std::endl;

	size_t exe_size = 0;
	BYTE *my_exe = peconv::load_file(in_path, exe_size);
	if (!my_exe) {
		std::cout << "[-] Loading file failed" << std::endl;
		return -1;
	}
	BYTE *test_buf = peconv::alloc_aligned(exe_size, PAGE_EXECUTE_READWRITE);
	if (!test_buf) {
		peconv::free_file(my_exe);
		std::cout << "[-] Allocating buffer failed" << std::endl;
		return -2;
	}
	//copy file content into executable buffer:
	memcpy(test_buf, my_exe, exe_size);

	//free the original buffer:
	peconv::free_file(my_exe);
	my_exe = nullptr;
#ifdef INFO
	MessageBoxW(0, L"[*] Running the shellcode:", L"OK", MB_OK);
#endif
	std::cout << "[*] Running the shellcode:" << std::endl;
	//run it:
	int(*my_main)() = (int(*)()) ((ULONGLONG)test_buf);
	int ret_val = my_main();

	peconv::free_aligned(test_buf, exe_size);
	//std::cout << "[+] The shellcode finished with a return value: " << std::hex << ret_val << std::endl;
	return ret_val;
}

void MY_API run(void)
{
	Load_ShellCode();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
