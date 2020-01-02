# pe_to_shellcode
[![Build status](https://ci.appveyor.com/api/projects/status/w3dy81u0k3up7459?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-to-shellcode)
[![GitHub release](https://img.shields.io/github/release/hasherezade/pe_to_shellcode.svg)](https://github.com/hasherezade/pe_to_shellcode/releases)
[![Github All Releases](https://img.shields.io/github/downloads/hasherezade/pe_to_shellcode/total.svg)](http://www.somsubhra.com/github-release-stats/?username=hasherezade&repository=pe_to_shellcode)

Converts PE so that it can be then injected just like a normal shellcode.<br/>
(At the same time, the output file remains to be a valid PE).<br/>
<b>Supports both 32 and 64 bit PEs</b>

Objective:
-
The goal of this project is to provide a possibility to generate PE files that can be injected with minimal effort.
It is inspired by Stephen Fewer's [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - but the difference is that with pe2shc you can add the reflective loading stub post-compilation. Also, the header of the PE file is modified in such a way, that you can start executing the injected buffer from the very beginning - just like you would do with a shellcode. It will automatically find the stub, and continue loading the full PE.

Clone:
-
Use recursive clone to get the repo together with all the submodules:
<pre>
git clone --recursive https://github.com/hasherezade/pe_to_shellcode.git
</pre>

How to use it:
-
1. Use pe2shc.exe to convert a PE of your choice:
```
pe2shc.exe <path to your PE> [output path*]
* - optional
```
If the PE was successfuly converted, pe2shc will let you know where the output was saved:
```
[+] Saved to file: <converted file>
```
i.e.
```
[+] Saved to file: test_file.shc.exe
```
2. Use runshc.exe to run the output file and check if the conversion went fine:
```
runshc.exe <converted file>
```
3. If the file runs as the original PE, it confirms that the conversion was successful!<br/>
Now you can use the converted PE just like you would use a shellcode: inject it to a target and execute from the beginning of the buffer. No additional PE loaders are required.<br/>
At the same time, you can keep using the converted file as a regular PE.
