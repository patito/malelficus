BITS 32

%assign origin 0x08048000

  ehdr:                                                 ; Elf32_Ehdr
                db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
        times 8 db      0
                dw      2                               ;   e_type
                dw      3                               ;   e_machine
                dd      1                               ;   e_version
                dd      origin + _start                          ;   e_entry
                dd      phdr - $$                       ;   e_phoff
                dd      sht1 - $$                       ;   e_shoff
                dd      0                               ;   e_flags
                dw      ehdrsize                        ;   e_ehsize
                dw      phdrsize                        ;   e_phentsize
                dw      1                               ;   e_phnum
                dw      shdrsize                        ;   e_shentsize
                dw      2                               ;   e_shnum
                dw      0                               ;   e_shstrndx

  ehdrsize      equ     $ - ehdr

  phdr:                                                 ; Elf32_Phdr
                dd      1                               ;   p_type
                dd      _start                               ;   p_offset
                dd      origin+_start                              ;   p_vaddr
                dd      origin+ _start                              ;   p_paddr
                dd      textsize                        ;   p_filesz
                dd      textsize                        ;   p_memsz
                dd      5                               ;   p_flags
                dd      0x1000                          ;   p_align

  phdrsize      equ     $ - phdr

  _start:
  ; your program here
    push dword 0x41414141
    mov edx, 4
    mov ecx, esp
    mov ebx, 1
    mov eax, 4
    int 0x80
    mov eax, 1
    mov ebx, 42
    int 0x80

  textsize      equ     $ - $$

sht1:
                dd      0   ; sh_name;		// Section name (string tbl index)
                dd      0   ; sh_type;		// Section type
                dd	0   ; sh_flags;		// Section flags
                dd      0   ; sh_addr;		// Section virtual addr at execution
                dd      0   ; sh_offset;		// Section file offset
                dd      0   ; sh_size;		// Section size in bytes
                dd      0   ; sh_link;		// Link to another section
                dd      0   ; sh_info;		// Additional section information
                dd      0   ; sh_addralign;		// Section alignment
                dd      0   ; sh_entsize;		// Entry size if section holds table
shdrsize        equ     $ - sht1

sht2:
                dd      27   ; sh_name;		// Section name (string tbl index)
                dd      1   ; sh_type;		// Section type
                dd	2   ; sh_flags;		// Section flags
                dd      origin + _start,   ; sh_addr;		// Section virtual addr at execution
                dd      _start   ; sh_offset;		// Section file offset
                dd      textsize   ; sh_size;		// Section size in bytes
                dd      0   ; sh_link;		// Link to another section
                dd      0   ; sh_info;		// Additional section information
                dd      1   ; sh_addralign;		// Section alignment
                dd      0   ; sh_entsize;		// Entry size if section holds table
