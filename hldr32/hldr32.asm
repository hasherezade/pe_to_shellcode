bits 32
%include "hldr32.inc"

;-----------------------------------------------------------------------------
;recover kernel32 image base
;-----------------------------------------------------------------------------

hldr_begin:
        pushad                           ;must save ebx/edi/esi/ebp
        push    tebProcessEnvironmentBlock
        pop     eax
        fs mov  eax, dword [eax]
        mov     eax, dword [eax + pebLdr]
        mov     esi, dword [eax + ldrInLoadOrderModuleList]
        lodsd
        xchg    eax, esi
        lodsd
        mov     ebp, dword [eax + mlDllBase]
        call    parse_exports

;-----------------------------------------------------------------------------
;API CRC table, null terminated
;-----------------------------------------------------------------------------

        dd      0E9258E7Ah               ;FlushInstructionCache
        dd      0C97C1FFFh               ;GetProcAddress
        dd      03FC1BD8Dh               ;LoadLibraryA
        dd      009CE0D4Ah               ;VirtualAlloc
        db      0

;-----------------------------------------------------------------------------
;parse export table
;-----------------------------------------------------------------------------

parse_exports:
        pop     esi
        mov     ebx, ebp
        mov     eax, dword [ebp + lfanew]
        add     ebx, dword [ebp + eax + IMAGE_DIRECTORY_ENTRY_EXPORT]
        cdq

walk_names:
        mov     eax, ebp
        mov     edi, ebp
        inc     edx
        add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames]
        add     edi, dword [eax + edx * 4]
        or      eax, -1

crc_outer:
        xor     al, byte [edi]
        push    8
        pop     ecx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     edi
        cmp     byte [edi], cl
        jne     crc_outer
        not     eax
        cmp     dword [esi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, ebp
        mov     eax, ebp
        add     edi, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals]
        movzx   edi, word [edi + edx * 2]
        add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions]
        mov     eax, dword [eax + edi * 4]
        add     eax, ebp
        push    eax
        lodsd
        sub     cl, byte [esi]
        jnz     walk_names

;-----------------------------------------------------------------------------
;allocate memory for mapping
;-----------------------------------------------------------------------------

        mov     esi, dword [esp + krncrcstk_size + 20h + 4]
        mov     ebp, dword [esi + lfanew]
        add     ebp, esi
        mov     ch, (MEM_COMMIT | MEM_RESERVE) >> 8
        push    PAGE_EXECUTE_READWRITE
        push    ecx
        push    dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohSizeOfImage]
        push    0
        call    dword [esp + 10h + krncrcstk.kVirtualAlloc]
        push    eax
        mov     ebx, esp

;-----------------------------------------------------------------------------
;map MZ header, NT Header, FileHeader, OptionalHeader, all section headers...
;-----------------------------------------------------------------------------

        mov     ecx, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohSizeOfHeaders]
        mov     edi, eax
        push    esi
        rep     movsb
        pop     esi

;-----------------------------------------------------------------------------
;map sections data
;-----------------------------------------------------------------------------

        mov     cx, word [ebp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhSizeOfOptionalHeader]
        lea     edx, dword [ebp + ecx + _IMAGE_NT_HEADERS.nthOptionalHeader]
        mov     cx, word [ebp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhNumberOfSections]
        xchg    edi, eax

map_section:
        pushad
        add     esi, dword [edx + _IMAGE_SECTION_HEADER.shPointerToRawData]
        add     edi, dword [edx + _IMAGE_SECTION_HEADER.shVirtualAddress]
        mov     ecx, dword [edx + _IMAGE_SECTION_HEADER.shSizeOfRawData]
        rep     movsb
        popad
        add     edx, _IMAGE_SECTION_HEADER_size
        loop    map_section

;-----------------------------------------------------------------------------
;import DLL
;-----------------------------------------------------------------------------

        pushad
        mov     cl, IMAGE_DIRECTORY_ENTRY_IMPORT
        mov     ebp, dword [ecx + ebp]  
        test    ebp, ebp    ;check if PE has import table
        je      import_popad     ;if import table not found, skip loading
        add     ebp, edi

import_dll:
        mov     ecx, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idName]
        jecxz   import_popad
        add     ecx, dword [ebx]
        push    ecx
        call    dword [ebx + mapstk_size + krncrcstk.kLoadLibraryA]
        xchg    ecx, eax
        mov     edi, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idFirstThunk]
        mov     esi, dword [ebp + _IMAGE_IMPORT_DESCRIPTOR.idOriginalFirstThunk]
        test    esi, esi    ;if OriginalFirstThunk is NULL... 
        cmove   esi, edi    ;use FirstThunk instead of OriginalFirstThunk
        add     esi, dword [ebx]
        add     edi, dword [ebx]

import_thunks:
        lodsd
        test    eax, eax
        je      import_next
        btr     eax, 31
        jc      import_push
        add     eax, dword [ebx]
        inc     eax
        inc     eax

import_push:
        push    ecx
        push    eax
        push    ecx
        call    dword [ebx + mapstk_size + krncrcstk.kGetProcAddress]
        pop     ecx
        stosd
        jmp     import_thunks

import_next:
        add     ebp, _IMAGE_IMPORT_DESCRIPTOR_size
        jmp     import_dll

import_popad:
        popad

;-----------------------------------------------------------------------------
;apply relocations
;-----------------------------------------------------------------------------

        mov     cl, IMAGE_DIRECTORY_ENTRY_RELOCS
        lea     edx, dword [ebp + ecx]   ;relocation entry in data directory
        add     edi, dword [edx]
        xor     ecx, ecx

reloc_block:
        pushad
        mov     ecx, dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock]
        sub     ecx, IMAGE_BASE_RELOCATION_size
        cdq

reloc_addr:
        movzx   eax, word [edi + edx + IMAGE_BASE_RELOCATION_size]
        push    eax
        and     ah, 0f0h
        cmp     ah, IMAGE_REL_BASED_HIGHLOW << 4
        pop     eax
        jne     reloc_abs                ;another type not HIGHLOW
        and     ah, 0fh
        add     eax, dword [edi + IMAGE_BASE_RELOCATION.rePageRVA]
        add     eax, dword [ebx]         ;new base address
        mov     esi, dword [eax]
        sub     esi, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohImageBasex]
        add     esi, dword [ebx]
        mov     dword [eax], esi
        xor     eax, eax

reloc_abs:
        test    eax, eax                 ;check for IMAGE_REL_BASED_ABSOLUTE
        jne     hldr_exit                ;not supported relocation type
        inc     edx
        inc     edx
        cmp     ecx, edx
        jg     reloc_addr
        popad
        add     ecx, dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock]
        add     edi, dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock]
        cmp     dword [edx + 4], ecx
        jg     reloc_block

;-----------------------------------------------------------------------------
;call entrypoint
;
;to a DLL main:
;push 0
;push 1
;push dword [ebx]
;mov  eax, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint]
;add  eax, dword [ebx]
;call eax
;
;to a RVA (an exported function's RVA, for example):
;
;mov  eax, 0xdeadf00d ; replace with addr
;add  eax, dword [ebx]
;call eax
;-----------------------------------------------------------------------------

        xor     ecx, ecx
        push    ecx
        push    ecx
        dec     ecx
        push    ecx
        call    dword [ebx + mapstk_size + krncrcstk.kFlushInstructionCache]
        mov     eax, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint]
        add     eax, dword [ebx]
        call    eax

;-----------------------------------------------------------------------------
;if fails or returns from host, restore stack and registers and return (somewhere)
;-----------------------------------------------------------------------------

hldr_exit:
        lea     esp, dword [ebx + mapstk_size + krncrcstk_size]
        popad
        ret     4 
hldr_end:

