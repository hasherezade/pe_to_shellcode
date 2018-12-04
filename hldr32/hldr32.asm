;HLDR (32 bit)
;version 1.1

bits 32
%include "hldr32.inc"

;-----------------------------------------------------------------------------
;parse kernel32.dll export table
;-----------------------------------------------------------------------------

hldr_begin:
        pushad
        call    parse_exports
        dd      0E9258E7Ah               ;FlushInstructionCache
        dd      0C97C1FFFh               ;GetProcAddress
        dd      03FC1BD8Dh               ;LoadLibraryA
        dd      009CE0D4Ah               ;VirtualAlloc
        db      0

parse_exports:
        push    tebProcessEnvironmentBlock
        pop     eax
        cdq
        fs mov  eax, dword [eax]
        mov     eax, dword [eax + pebLdr]
        mov     esi, dword [eax + ldrInLoadOrderModuleList]
        lodsd
        xchg    eax, esi
        lodsd
        mov     ebp, dword [eax + mlDllBase]
        mov     ebx, ebp
        mov     eax, dword [ebp + lfanew]
        add     ebx, dword [eax + ebp + IMAGE_DIRECTORY_ENTRY_EXPORT]
        pop     esi

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

        pop     eax
        mov     esi, dword [esp + krncrcstk_size + 20h + 4]
        mov     edx, dword [esi + lfanew]
        lea     ebp, dword [esi + edx + 7fh]
        mov     ch, (MEM_COMMIT | MEM_RESERVE) >> 8
        push    PAGE_EXECUTE_READWRITE
        push    ecx
        push    dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohSizeOfImage - 7fh]
        push    0
        call    eax
        push    eax
        mov     ebx, esp

;-----------------------------------------------------------------------------
;map MZ header, NT Header, FileHeader, OptionalHeader, all section headers...
;-----------------------------------------------------------------------------

        mov     ecx, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohSizeOfHeaders - 7fh]
        mov     edi, eax
        push    esi
        rep     movsb
        pop     esi

;-----------------------------------------------------------------------------
;map sections data
;-----------------------------------------------------------------------------

        mov     cx, word [ebp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhSizeOfOptionalHeader - 7fh]
        lea     edx, dword [ebp + ecx + _IMAGE_NT_HEADERS.nthOptionalHeader - 7fh]
        mov     cx, word [ebp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhNumberOfSections - 7fh]
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
;parse import DLL
;-----------------------------------------------------------------------------

        pushad
        mov     ebp, dword [ecx + ebp + IMAGE_DIRECTORY_ENTRY_IMPORT - 7fh]
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
        test    esi, esi
        cmove   esi, edi                 ;if OriginalFirstThunk is NULL, esi = edi = FirstThunk
        add     esi, dword [ebx]
        add     edi, dword [ebx]
        add     ebp, _IMAGE_IMPORT_DESCRIPTOR_size

import_thunks:
        lodsd
        btr     eax, 31
        jc      import_push
        test    eax, eax
        je      import_dll
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

import_popad:
        popad

;-----------------------------------------------------------------------------
;push FlushInstructionCache(0xffffffff, 0, 0) at an earlier time
;-----------------------------------------------------------------------------

        push    ecx                      ;FlushInstructionCache
        push    ecx                      ;FlushInstructionCache
        dec     ecx                      ;FlushInstructionCache
        push    ecx                      ;FlushInstructionCache
        inc     ecx

;-----------------------------------------------------------------------------
;parse base relocation table
;-----------------------------------------------------------------------------

        add     edi, dword [ebp + IMAGE_DIRECTORY_ENTRY_RELOCS - 7fh]

reloc_block:
        push    IMAGE_BASE_RELOCATION_size
        pop     edx

reloc_addr:
        movzx   eax, word [edi + edx]
        push    eax
        and     ah, 0f0h
        cmp     ah, IMAGE_REL_BASED_HIGHLOW << 4
        pop     eax
        jne     reloc_abs                ;another type not HIGHLOW
        and     ah, 0fh
        add     eax, dword [edi + IMAGE_BASE_RELOCATION.rePageRVA]
        add     eax, dword [ebx]         ;new base address        
        mov     esi, dword [eax]
        sub     esi, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohImageBasex - 7fh]
        add     esi, dword [ebx]
        mov     dword [eax], esi
        xor     eax, eax

reloc_abs:
        test    eax, eax                 ;check for IMAGE_REL_BASED_ABSOLUTE
        jne     hldr_exit                ;not supported relocation type
        inc     edx
        inc     edx
        cmp     dword [edi + IMAGE_BASE_RELOCATION.reSizeOfBlock], edx
        jne     reloc_addr
        add     ecx, edx
        add     edi, edx
        cmp     dword [ebp + IMAGE_DIRECTORY_ENTRY_RELOCS + 4 - 7fh], ecx
        jne     reloc_block

;-----------------------------------------------------------------------------
;call entrypoint
;-----------------------------------------------------------------------------

        call    dword [ebx + mapstk_size + krncrcstk.kFlushInstructionCache]
        mov     eax, dword [ebp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint - 7fh]
        add     eax, dword [ebx]
        push    ebx
        call    eax
        pop     ebx

hldr_exit:
        lea     esp, dword [ebx + mapstk_size + krncrcstk_size]
        popad
        ret     4 
hldr_end: