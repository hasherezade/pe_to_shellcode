# pe_to_shellcode
[![Build status](https://ci.appveyor.com/api/projects/status/w3dy81u0k3up7459?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-to-shellcode)
[![GitHub release](https://img.shields.io/github/release/hasherezade/pe_to_shellcode.svg)](https://github.com/hasherezade/pe_to_shellcode/releases)
[![Github All Releases](https://img.shields.io/github/downloads/hasherezade/pe_to_shellcode/total.svg)](https://github.com/hasherezade/pe_to_shellcode/releases)
[![Github Latest Release](https://img.shields.io/github/downloads/hasherezade/pe_to_shellcode/latest/total.svg)](https://github.com/hasherezade/pe_to_shellcode/releases)

Converts PE so that it can be then injected just like a normal shellcode.<br/>
(At the same time, the output file remains to be a valid PE).<br/>
<b>Supports both 32 and 64 bit PEs</b>

*Authors: [@hasherezade](https://github.com/hasherezade) & [@hh86](https://github.com/86hh)*

Objective
-
The goal of this project is to provide a possibility to generate PE files that can be injected with minimal effort.
It is inspired by Stephen Fewer's [ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection) - but the difference is that with pe2shc you can add the reflective loading stub post-compilation. Also, the header of the PE file is modified in such a way, that you can start executing the injected buffer from the very beginning - just like you would do with a shellcode. It will automatically find the stub, and continue loading the full PE.

Scope of the project
-
🟢 The stub supports only basic structures of PE format, such as:
+ relocations
+ imports
+ TLS callbacks (called once, before the Entry Point is executed)

Please keep in mind, that although for the majority of PE files this is sufficient, some executables you encounter may be using other, more complex aspects of the PE format. It means, **not every PE can be successfuly converted to a shellcode**.

🚫 Examples of currently not supported elements:
+ exceptions (if the executable you converted will be run as a shellcode, and throw the exception, the appropriate exception handler will not be found, and the application will crash)
+ Delay Load Imports (only the basic Import Table support is implemented)
+ MUI files (if the executable you converted expects some elements of the GUI have to be loaded from a MUI file, it won't work)

Builds
-
📦 ⚙️ Download the latest [release](https://github.com/hasherezade/pe_to_shellcode/releases).

Clone
-
Use recursive clone to get the repo together with all the submodules:

```console
git clone --recursive https://github.com/hasherezade/pe_to_shellcode.git
```

How to use it
-
1. Use **pe2shc.exe** to convert a PE of your choice:
```
pe2shc.exe <path to your PE> [output path*]
* - optional
```
If the PE was successfuly converted, **pe2shc** will let you know where the output was saved:
```
[+] Saved to file: <converted file>
```
i.e.
```
[+] Saved to file: test_file.shc.exe
```
2. Use **runshc.exe**(*) to run the output file and check if the conversion went fine.
```
runshc.exe <converted file>
```

(*)Warning: remember to use the version of **runshc** with a bitness appropriate to your converted application (32 or 64 bit) - otherwise the application will crash!

3. If the file runs as the original PE, it confirms that the conversion was successful!<br/>
Now you can use the converted PE just like you would use a shellcode: inject it to a target and execute from the beginning of the buffer. No additional PE loaders are required.<br/>
At the same time, you can keep using the converted file as a regular PE.
