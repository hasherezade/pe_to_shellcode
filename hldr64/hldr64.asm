bits 64

%include "hldr64.inc"

;-----------------------------------------------------------------------------
;here begins HLDR64
;-----------------------------------------------------------------------------

hldr64_begin:
        push    rbx
        push    rsi
        push    rdi
        push    r12
        push    r8
        push    r9
regstksize      equ     30h

;-----------------------------------------------------------------------------
;recover kernel32 image base
;-----------------------------------------------------------------------------

        push    tebProcessEnvironmentBlock
        pop     rsi
        gs lodsq
        mov     rax, qword [rax + pebLdr]
        mov     rsi, qword [rax + InMemoryOrderModuleList]
        lodsq
        xchg    rax, rsi
        lodsq
        mov     rbp, qword [rax + mDllBase]
        call    parse_exports
        dd      0E9258E7Ah               ;FlushInstructionCache
        dd      0C97C1FFFh               ;GetProcAddress
        dd      03FC1BD8Dh               ;LoadLibraryA
        dd      009CE0D4Ah               ;VirtualAlloc
        db      0

;-----------------------------------------------------------------------------
;parse export table 
;-----------------------------------------------------------------------------

parse_exports:
        pop     rsi
        mov     eax, dword [rbp + lfanew]
        mov     ebx, dword [rbp + rax + IMAGE_DIRECTORY_ENTRY_EXPORT]
        add     rbx, rbp
        cdq

walk_names:
        inc     edx
        mov     eax, dword [rbx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames]
        add     rax, rbp
        mov     edi, dword [rax + rdx * 4]
        add     rdi, rbp
        or      eax, -1

crc_outer:
        xor     al, byte [rdi]
        push    8
        pop     rcx

crc_inner:
        shr     eax, 1
        jnc     crc_skip
        xor     eax, 0edb88320h

crc_skip:
        loop    crc_inner
        inc     rdi
        cmp     byte [rdi], cl
        jne     crc_outer
        not     eax
        cmp     dword [rsi], eax
        jne     walk_names

;-----------------------------------------------------------------------------
;exports must be sorted alphabetically, otherwise GetProcAddress() would fail
;this allows to push addresses onto the stack, and the order is known
;-----------------------------------------------------------------------------

        mov     edi, dword [rbx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals]
        add     rdi, rbp
        movzx   edi, word [rdi + rdx * 2]
        mov     eax, dword [rbx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions]
        add     rax, rbp
        mov     eax, dword [rax + rdi * 4]
        add     rax, rbp
        push    rax
        lodsd
        sub     cl, byte [rsi]
        jne     walk_names

;-----------------------------------------------------------------------------
;allocate space for mapstk, and make stack frame
;allocate space for shadow stack only once then align stack because at this time
;we don't know if aligned for sure
;-----------------------------------------------------------------------------

        push    rcx
        push    rcx
        push    rsp
        pop     rbx
        sub     rsp, 40h                 ;only 20h bytes required for shadow stack
        and     rsp, -10h                ;align on 16-byte boundary

;-----------------------------------------------------------------------------
;allocate memory for mapping
;-----------------------------------------------------------------------------

        mov     rsi, qword [rbx + mapstk_size + krncrcstk_size + regstksize + 8]
        mov     ebp, dword [rsi + lfanew]
        add     rbp, rsi
        push    PAGE_EXECUTE_READWRITE
        pop     r9
        mov     r8d, MEM_COMMIT | MEM_RESERVE
        mov     edx, dword [rbp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohSizeOfImage]
        call    qword [rbx + mapstk_size + krncrcstk.kVirtualAlloc]
        mov     qword [rbx], rax

;-----------------------------------------------------------------------------
;map MZ header, NT Header, FileHeader, OptionalHeader, all section headers...
;-----------------------------------------------------------------------------

        mov     ecx, dword [rbp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohSizeOfHeaders]
        push    rax
        pop     rdi
        push    rsi
        rep     movsb
        pop     rsi

;-----------------------------------------------------------------------------
;map sections data
;-----------------------------------------------------------------------------

        mov     cx, word [rbp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhSizeOfOptionalHeader]
        lea     rdx, qword [rbp + rcx + _IMAGE_NT_HEADERS.nthOptionalHeader]
        mov     cx, word [rbp + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhNumberOfSections]

map_section:
        push    rcx
        push    rsi
        mov     ecx, dword [rdx + _IMAGE_SECTION_HEADER.shPointerToRawData]
        add     rsi, rcx 
        mov     edi, dword [rdx + _IMAGE_SECTION_HEADER.shVirtualAddress]
        add     rdi, rax
        mov     ecx, dword [rdx + _IMAGE_SECTION_HEADER.shSizeOfRawData]
        rep     movsb
        pop     rsi
        pop     rcx
        add     rdx, _IMAGE_SECTION_HEADER_size
        loop    map_section

;-----------------------------------------------------------------------------
;import DLL
;-----------------------------------------------------------------------------

        mov     r12, rbp
        mov     cl, IMAGE_DIRECTORY_ENTRY_IMPORT
        mov     ebp, dword [rcx + rbp]
        test    ebp, ebp                 ;check if PE has import table
        je      import_poprbp            ;if import table not found, skip loading
        add     rbp, rax

import_dll:
        mov     ecx, dword [rbp + _IMAGE_IMPORT_DESCRIPTOR.idName]
        jecxz   import_poprbp
        add     rcx, qword [rbx]
        call    qword [rbx + mapstk_size + krncrcstk.kLoadLibraryA]
        mov     qword [rbx + mapstk.hModule], rax
        mov     edi, dword [rbp + _IMAGE_IMPORT_DESCRIPTOR.idFirstThunk]
        mov     esi, dword [rbp + _IMAGE_IMPORT_DESCRIPTOR.idOriginalFirstThunk]
        test    esi, esi
        cmove   esi, edi                 ;if OriginalFirstThunk is NULL, esi = edi = FirstThunk
        add     rdi, qword [rbx]
        add     rsi, qword [rbx]
        add     rbp, _IMAGE_IMPORT_DESCRIPTOR_size

import_thunks:
        lodsq
        test    rax, rax
        je      import_dll
        btr     rax, 63
        jc      import_mov
        add     rax, qword [rbx]
        inc     rax
        inc     rax

import_mov:
        push    rax
        pop     rdx
        mov     rcx, qword [rbx + mapstk.hModule]
        call    qword [rbx + mapstk_size + krncrcstk.kGetProcAddress]
        stosq
        jmp     import_thunks

import_poprbp:
        mov     rbp, r12                 ;restore because r12 uses prefix

;-----------------------------------------------------------------------------
;apply relocations
;-----------------------------------------------------------------------------

        mov     edi, dword [rbp + IMAGE_DIRECTORY_ENTRY_RELOCS]
        add     rdi, qword [rbx]

reloc_block:
        push    IMAGE_BASE_RELOCATION_size
        pop     rdx

reloc_addr:
        movzx   rax, word [rdi + rdx]
        push    rax
        and     ah, 0f0h
        cmp     ah, IMAGE_REL_BASED_DIR64 << 4
        pop     rax
        jne     reloc_abs                ;another type not DIR64
        and     ah, 0fh
        add     eax, dword [rdi + IMAGE_BASE_RELOCATION.rePageRVA]
        add     rax, qword [rbx]         ;new base address        
        mov     rsi, qword [rax]
        sub     rsi, qword [rbp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohImageBasex]
        add     rsi, qword [rbx]
        mov     qword [rax], rsi
        xor     eax, eax

reloc_abs:
        test    eax, eax                 ;check for IMAGE_REL_BASED_ABSOLUTE
        jne     hldr_exit                ;not supported relocation type
        inc     edx
        inc     edx
        cmp     dword [rdi + IMAGE_BASE_RELOCATION.reSizeOfBlock], edx
        jg     reloc_addr
        add     ecx, edx
        add     rdi, rdx
        cmp     dword [rbp + IMAGE_DIRECTORY_ENTRY_RELOCS + 4], ecx
        jg     reloc_block

reloc_finished:
;-----------------------------------------------------------------------------
;call entrypoint
;-----------------------------------------------------------------------------

        xor     r8, r8
        xor     edx, edx
        or      ecx, -1
        call    qword [rbx + mapstk_size + krncrcstk.kFlushInstructionCache]
        mov     eax, dword [rbp + _IMAGE_NT_HEADERS.nthOptionalHeader + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint]
        add     rax, qword [rbx]
        call    rax

;-----------------------------------------------------------------------------
;if fails or returns from host, restore stack and registers and return (somewhere)
;-----------------------------------------------------------------------------

hldr_exit:
        lea     rsp, qword [rbx + mapstk_size + krncrcstk_size]
        pop     r9
        pop     r8
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbx
        ret     8

