BITS 32
	%assign origin 0x08048000

ehdr:                                                 ; Elf32_Ehdr
        db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
        times 8 db      0
        dw      2                               ;   e_type
        dw      3                               ;   e_machine
        dd      1                               ;   e_version
                dd      origin+main                          ;   e_entry
                dd      phdr - $$                       ;   e_phoff
                dd      sht_0 - $$                               ;   e_shoff
                dd      0                               ;   e_flags
                dw      ehdrsize                        ;   e_ehsize
                dw      phdrsize                        ;   e_phentsize
                dw      1                               ;   e_phnum
                dw      shentsize                               ;   e_shentsize
                dw      2                               ;   e_shnum
                dw      0                               ;   e_shstrndx

  ehdrsize      equ     $ - ehdr

  phdr:                                                 ; Elf32_Phdr
                dd      1                               ;   p_type
                dd      main                               ;   p_offset
                dd      origin+main                              ;   p_vaddr
                dd      origin+main                              ;   p_paddr
                dd      filesize                        ;   p_filesz
                dd      filesize                        ;   p_memsz
                dd      5                               ;   p_flags
                dd      0x1000                          ;   p_align

  phdrsize      equ     $ - phdr

  main:

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

  filesize      equ     $ - main
  
sht_0:
	dd	0x0		; sh_name Section name (string tbl index)
	dd	0x0		; sh_type Section type
	dd	0x0		; sh_flags Section flags
	dd	0x00000000	; sh_addr Section virtual addr at execution
	dd	0x0		; sh_offset Section file offset
	dd	0x0		; sh_size Section size in bytes
	dd	0x0		; sh_link Link to another section
	dd	0x0		; sh_info Additional section information
	dd	0x0		; sh_addralign Section alignment
	dd	0x0		; sh_entsize Entry size if section holds table
shentsize	equ $ - sht_0


sht_1:
	dd	0x0		; sh_name Section name (string tbl index)
	dd	0x1		; sh_type Section type
	dd	0x2		; sh_flags Section flags
	dd	origin+main	; sh_addr Section virtual addr at execution
	dd	main		; sh_offset Section file offset
	dd	filesize		; sh_size Section size in bytes
	dd	0x0		; sh_link Link to another section
	dd	0x0		; sh_info Additional section information
	dd	0x1		; sh_addralign Section alignment
	dd	0x0		; sh_entsize Entry size if section holds table