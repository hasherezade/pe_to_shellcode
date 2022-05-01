cl /c /GS- /FA peloader.cpp
masm_shc.exe peloader.asm peloader1.asm
ml peloader1.asm /link /entry:main
