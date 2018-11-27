# pe_to_shellcode
[![Build status](https://ci.appveyor.com/api/projects/status/w3dy81u0k3up7459?svg=true)](https://ci.appveyor.com/project/hasherezade/pe-to-shellcode)

Converts PE so that it can be then injected just like a normal shellcode.<br/>
Currently only 32 bit PE files are supported.<br/>
<b>WARNING: This is an early draft of this tool! It is available for experimental purposes only. I don't guarantee stability of the outputs.</b>

Clone:
-
Use recursive clone to get the repo together with all the submodules:
<pre>
git clone --recursive https://github.com/hasherezade/pe_to_shellcode.git
</pre>
Latest builds*:
-
*those builds are available for testing and they may be ahead of the official release:
+ [pe_to_shellcode32.exe](https://goo.gl/LfJaVZ) - PE to shellcode converter
+ [test_shc32.exe](https://goo.gl/xi3fzQ) - a utility to test the shellcode (loads and deploys)
<hr/>
