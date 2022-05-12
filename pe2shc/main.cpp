#include <windows.h>
#include <iostream>

#include "peconv.h"
#include "resource.h"

#define VERSION "1.1"

bool overwrite_hdr(BYTE *my_exe, size_t exe_size, DWORD raw, bool is64b)
{
	const size_t value_pos = 8;
	size_t redir_size = 0;
	BYTE* redir_code = nullptr;

	BYTE redir_code32_64[] = "\x4D" //dec ebp
		"\x5A" //pop edx
		"\x45" //inc ebp
		"\x52" //push edx
		"\xE8\x00\x00\x00\x00" //call <next_line>
		"\x5B" // pop ebx
		"\x48\x83\xEB\x09" // sub ebx,9
		"\x53" // push ebx (Image Base)
		"\x48\x81\xC3" // add ebx,
		"\x59\x04\x00\x00" // value
		"\xFF\xD3" // call ebx
		"\xc3"; // ret

	BYTE redir_code32[] = "\x4D" //dec ebp
		"\x5A" //pop edx
		"\x45" //inc ebp
		"\x52" //push edx
		"\xE8\x00\x00\x00\x00" //call <next_line>
		"\x58" // pop eax
		"\x83\xE8\x09" // sub eax,9
		"\x50" // push eax (Image Base)
		"\x05" // add eax,
		"\x59\x04\x00\x00" // value
		"\xFF\xD0" // call eax
		"\xc3"; // ret

	BYTE redir_code64[] = "\x4D\x5A" //pop r10
		"\x45\x52" //push r10
		"\xE8\x00\x00\x00\x00" //call <next_line>
		"\x59" // pop rcx
		"\x48\x83\xE9\x09" // sub rcx,9 (rcx -> Image Base)
		"\x48\x8B\xC1" // mov rax,rcx 
		"\x48\x05" // add eax,
		"\x59\x04\x00\x00" // value
		"\xFF\xD0" // call eax
		"\xc3"; // ret

#ifdef OLD_LOADER
	redir_code = redir_code32_64;
	redir_size = sizeof(redir_code32_64);
#else
	redir_code = redir_code32;
	redir_size = sizeof(redir_code32);

	if (is64b) {
		redir_code = redir_code64;
		redir_size = sizeof(redir_code64);
	}
#endif
	if (!redir_code) return false;

	size_t offset = redir_size - value_pos;
	memcpy(redir_code + offset, &raw, sizeof(DWORD));
	memcpy(my_exe, redir_code, redir_size);
	return true;
}

BYTE* shellcodify(BYTE *my_exe, size_t exe_size, size_t &out_size, bool is64b)
{
	out_size = 0;
	size_t stub_size = 0;
	int res_id = is64b ? STUB64 : STUB32;
	BYTE *stub = peconv::load_resource_data(stub_size, res_id);
	if (!stub) {
		std::cerr << "[ERROR] Stub not loaded" << std::endl;
		return nullptr;
	}
	size_t ext_size = exe_size + stub_size;
	BYTE *ext_buf = peconv::alloc_aligned(ext_size, PAGE_READWRITE);
	if (!ext_buf) {
		return nullptr;
	}
	memcpy(ext_buf, my_exe, exe_size);
	memcpy(ext_buf + exe_size, stub, stub_size);

	DWORD raw_addr = exe_size;
	overwrite_hdr(ext_buf, ext_size, raw_addr, is64b);

	out_size = ext_size;
	return ext_buf;
}

template <typename IMAGE_TLS_DIRECTORY>
bool has_tls_callbacks(BYTE *my_exe, size_t exe_size)
{
	IMAGE_DATA_DIRECTORY* tls_dir = peconv::get_directory_entry(my_exe, IMAGE_DIRECTORY_ENTRY_TLS);
	if (!tls_dir) return false;

	IMAGE_TLS_DIRECTORY* tls = peconv::get_type_directory<IMAGE_TLS_DIRECTORY>((HMODULE)my_exe, IMAGE_DIRECTORY_ENTRY_TLS);
	if (!tls) return false;

	ULONGLONG base = peconv::get_image_base(my_exe);
	ULONGLONG callback_rva = tls->AddressOfCallBacks;
	if (callback_rva > base) {
		callback_rva -= base;
	}
	if (!peconv::validate_ptr(my_exe, exe_size, my_exe + callback_rva, sizeof(ULONGLONG))) {
		return false;
	}
	ULONGLONG *callback_addr = (ULONGLONG *)(my_exe + callback_rva);
	if (callback_addr == 0) {
		return false;
	}
	if (*callback_addr == 0) {
		return false;
	}
	return true;
}

bool is_supported_pe(BYTE *my_exe, size_t exe_size)
{
	if (!my_exe) return false;
	if (!peconv::has_relocations(my_exe)) {
		std::cerr << "[ERROR] The PE must have relocations!" << std::endl;
		return false;
	}
	if (peconv::get_subsystem(my_exe) != IMAGE_SUBSYSTEM_WINDOWS_GUI) {
		std::cout << "[INFO] This is a console application." << std::endl;
	}
	IMAGE_DATA_DIRECTORY* dotnet_dir = peconv::get_directory_entry(my_exe, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	if (dotnet_dir) {
		std::cerr << "[ERROR] .NET applications are not supported!" << std::endl;
		return false;
	}
	IMAGE_DATA_DIRECTORY* tls_dir = peconv::get_directory_entry(my_exe, IMAGE_DIRECTORY_ENTRY_TLS);
	if (tls_dir) {
		bool has_callback = false;
		if (!peconv::is64bit(my_exe)) {
			if (has_tls_callbacks<IMAGE_TLS_DIRECTORY32>(my_exe, exe_size)) {
				has_callback = true;
			}
		}
		else {
			if (has_tls_callbacks<IMAGE_TLS_DIRECTORY64>(my_exe, exe_size)) {
				has_callback = true;
			}
		}
		if (has_callback) {
			std::cout << "[INFO] This application has TLS callbacks." << std::endl;
		}
	}
	return true;
}

bool is_supported_pe(const std::string &in_path)
{
	std::cout << "Reading module from: " << in_path << std::endl;
	size_t exe_size = 0;
	BYTE *my_exe = peconv::load_pe_module(in_path.c_str(), exe_size, false, false);
	if (!my_exe) {
		std::cerr << "[ERROR] Could not read the input file!" << std::endl;
		return false;
	}

	bool is_ok = is_supported_pe(my_exe, exe_size);
	peconv::free_pe_buffer(my_exe);

	if (!is_ok) {
		std::cerr << "[ERROR] Not supported input file!" << std::endl;
		return false;
	}
	return true;
}

std::string make_out_name(std::string input_file)
{
	size_t found_indx = input_file.find_last_of(".");
	std::string ext = input_file.substr(found_indx + 1);
	std::string name = input_file.substr(0, found_indx);
	return name + ".shc." + ext;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		std::cout << "~ pe2shc v." << VERSION << " ~\n"
			<< "Converts PE into shellcode.\nFor 32 & 64 bit PEs.\n";
		std::cout << "Args: <input_file> [output_file]" << std::endl;
		system("pause");
		return 0;
	}
#ifdef OLD_LOADER
	std::cout << "Using: Loader v1\n";
#else
	std::cout << "Using: Loader v2\n";
#endif
	std::string in_path = argv[1];
	std::string  out_str = make_out_name(in_path);
	if (argc > 2) {
		out_str = argv[2];
	}

	if (!is_supported_pe(in_path)) {
		return -2;
	}

	size_t exe_size = 0;
	BYTE *my_exe = peconv::load_pe_module(in_path.c_str(), exe_size, false, false);
	if (!my_exe) {
		std::cout << "[-] Could not read the input file!" << std::endl;
		return -1;
	}

	bool is64b = peconv::is64bit(my_exe);
	size_t ext_size = 0;
	BYTE *ext_buf = shellcodify(my_exe, exe_size, ext_size, is64b);
	if (!ext_buf) {
		std::cerr << "[ERROR] Adding the stub failed!" << std::endl;
		peconv::free_pe_buffer(my_exe);
		return -3;
	}
	// remap pe to raw == virtual, so that remapping on load will not be required
	peconv::t_pe_dump_mode dump_mode = peconv::PE_DUMP_REALIGN;
	ULONGLONG current_base = peconv::get_image_base(ext_buf);
	if (peconv::dump_pe(out_str.c_str(), ext_buf, ext_size, current_base, dump_mode)) {
		std::cout << "[INFO] Saved as: " << out_str << std::endl;
	}
	else {
		std::cerr << "[ERROR] Failed to save the output!" << std::endl;
	}
	peconv::free_pe_buffer(my_exe);
	peconv::free_aligned(ext_buf);
	return 0;
}
