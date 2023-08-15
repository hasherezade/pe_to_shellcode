Loader is the part dedicated to manual loading of a PE. It is automatically added to your executable during the process of conversion (shellcodification). So, when you use pe_to_shellcode, two main things are done to your exe: 
1) the loader is appended
2) the header is modified, to redirect the execution to the loader - thanks to this, after the conversion the PE can be injected and executed starting from its beginning.

Loader is built separately from the main executable.
+ Buiding requires [masm_shc.exe](https://github.com/hasherezade/masm_shc/releases).
+ More details described [here](https://github.com/hasherezade/masm_shc).
