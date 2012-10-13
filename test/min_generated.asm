BITS 32
        %assign origin 0x08048000

ehdr:					; Elf32_Ehdr
        db	0x7f, "ELF", 1, 1, 1, 0		; e_ident
        times 8	db      0
        dw	2			; e_type
        dw	3			; e_machine
        dd	1			; e_version
        dd	0x08048054			; e_entry
        dd	0x34		; e_phoff
        dd	0x78			; e_shoff
        dd	0			; e_flags
        dw	0x34		; e_ehsize
        dw	0x20		; e_phentsize
        dw	1			; e_phnum
        dw	0x28			; e_shentsize
        dw	2			; e_shnum
        dw	0			; e_shstrndx
        ehdrsize	equ	$ - ehdr		; ehdr size
	; PHT 0
phdr_0:					; Elf32_Phdr
        dd	0x1			; p_type
        dd	0x54			; p_offset
        dd	0x8048054			; p_vaddr
        dd	0x8048054			; p_paddr
        dd	36			; p_filesz
        dd	36			; p_memsz
        dd	5			; p_flags
        dd	0x1000			; p_align

        phdrsize	equ	$ - phdr_0

	; Program
	; Disassembly of section 1
.section_1:
push       0x41414141
mov        edx, 0x00000004
mov        ecx, esp
mov        ebx, 0x00000001
mov        eax, 0x00000004
int        0x80
mov        eax, 0x00000001
mov        ebx, 0x0000002A
int        0x80



	; Section Header Table
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


sht_1:
        dd	0x0		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048054	; sh_addr Section virtual addr at execution
        dd	0x54		; sh_offset Section file offset
        dd	0x24		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x1		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table



