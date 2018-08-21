#include <windows.h>
#include <iostream>

#include "peconv.h"
#include "resource.h"

#define VERSION "0.2"

bool overwrite_hdr(BYTE *my_exe, size_t exe_size, DWORD raw)
{
	BYTE redir_code[] = "\x4D\x5A"
		"\xE8\x00\x00\x00\x00"
		"\x5B" // pop ebx
		"\x83\xEB\x07" // sub ebx,7
		"\x53" // push ebx (Image Base)
		"\x81\xC3" // add ebx,
		"\x59\x04\x00\x00" // value
		"\xFF\xD3" // call ebx
		"\xc3"; // ret

	size_t offset = sizeof(redir_code) - 8;

	memcpy(redir_code + offset, &raw, sizeof(DWORD));
	memcpy(my_exe, redir_code, sizeof(redir_code));
	return true;
}

BYTE* shellcodify32(BYTE *my_exe, size_t exe_size, size_t &out_size)
{
	out_size = 0;
	size_t stub_size = 0;
	BYTE *stub32 = peconv::load_resource_data(stub_size, STUB32);
	if (!stub32) {
		std::cout << "Stub not loaded" << std::endl;
		return nullptr;
	}
	size_t ext_size = exe_size + stub_size;
	BYTE *ext_buf = peconv::alloc_aligned(ext_size, PAGE_READWRITE);
	if (!ext_buf) {
		return nullptr;
	}
	memcpy(ext_buf, my_exe, exe_size);
	memcpy(ext_buf + exe_size, stub32, stub_size);

	DWORD raw_addr = exe_size;
	overwrite_hdr(ext_buf, ext_size, raw_addr);

	out_size = ext_size;
	return ext_buf;
}

bool is_supported_pe(BYTE *my_exe, size_t exe_size)
{
	if (!my_exe) return false;
	WORD arch = peconv::get_nt_hdr_architecture(my_exe);
	if (arch != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		std::cout << "Only PE 32bit is supported!" << std::endl;
		return false;
	}
	if (!peconv::has_relocations(my_exe)) {
		std::cout << "The PE must have relocations!" << std::endl;
		return false;
	}
	if (peconv::get_subsystem(my_exe) != IMAGE_SUBSYSTEM_WINDOWS_GUI) {
		std::cout << "Subsystem must be GUI!" << std::endl;
		return false;
	}
	IMAGE_DATA_DIRECTORY* dotnet_dir = peconv::get_directory_entry(my_exe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	if (dotnet_dir) {
		std::cout << ".NET applications are not supported!" << std::endl;
		return false;
	}
	IMAGE_DATA_DIRECTORY* tls_dir = peconv::get_directory_entry(my_exe, IMAGE_DIRECTORY_ENTRY_TLS);
	if (tls_dir) {
		std::cout << "Applications with TLS callbacks are not supported!" << std::endl;
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "PE to shellcode v." << VERSION << " - EXPERIMENTAL"<< std::endl;
		std::cout << "Args: <input_file> [output_file]" << std::endl;
		system("pause");
		return 0;
	}

	size_t exe_size = 0;
	std::string in_path = argv[1];
	std::string  out_str = in_path + ".shc";
	if (argc > 2) {
		out_str = argv[2];
	}

	std::cout << "Reading module from: " << in_path << std::endl;
	BYTE *my_exe = peconv::load_file(in_path.c_str(), exe_size);
	if (!my_exe) {
		system("pause");
		return -1;
	}
	if (!is_supported_pe(my_exe, exe_size)) {
		std::cout << "[-] Not supported input file!" << std::endl;
		peconv::free_file(my_exe);
		return -2;
	}
	size_t ext_size = 0;
	BYTE *ext_buf = shellcodify32(my_exe, exe_size, ext_size);
	if (!ext_buf) {
		std::cout << "[-] Adding the stub failed!" << std::endl;
		peconv::free_file(my_exe);
		return -3;
	}
	if (peconv::dump_to_file(out_str.c_str(), ext_buf, ext_size)) {
		std::cout << "[+] Saved to file: " << out_str << std::endl;
	}
	else {
		std::cout << "[-] Failed to save the output!" << std::endl;
	}
	peconv::free_file(my_exe);
	peconv::free_aligned(ext_buf);
	return 0; 
}
