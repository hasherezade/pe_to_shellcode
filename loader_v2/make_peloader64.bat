cl /c /GS- /FA peloader.cpp
masm_shc.exe peloader.asm peloader2.asm
ml64 peloader2.asm /link /entry:AlignRSP