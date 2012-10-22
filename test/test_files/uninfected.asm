BITS 32
        %assign origin 0x08048000

ehdr:					; Elf32_Ehdr
        db	0x7f, "ELF", 1, 1, 1, 0		; e_ident
        times 8	db      0
        dw	2			; e_type
        dw	3			; e_machine
        dd	1			; e_version
        dd	0x08048330			; e_entry
        dd	0x34		; e_phoff
        dd	0x113c			; e_shoff
        dd	0			; e_flags
        dw	0x34		; e_ehsize
        dw	0x20		; e_phentsize
        dw	9			; e_phnum
        dw	0x28			; e_shentsize
        dw	30			; e_shnum
        dw	27			; e_shstrndx
        ehdrsize	equ	$ - ehdr		; ehdr size
	; PHT 0
phdr_0:					; Elf32_Phdr
        dd	0x6			; p_type
        dd	0x34			; p_offset
        dd	0x8048034			; p_vaddr
        dd	0x8048034			; p_paddr
        dd	288			; p_filesz
        dd	288			; p_memsz
        dd	5			; p_flags
        dd	0x4			; p_align
	; PHT 1
phdr_1:					; Elf32_Phdr
        dd	0x3			; p_type
        dd	0x154			; p_offset
        dd	0x8048154			; p_vaddr
        dd	0x8048154			; p_paddr
        dd	19			; p_filesz
        dd	19			; p_memsz
        dd	4			; p_flags
        dd	0x1			; p_align
	; PHT 2
phdr_2:					; Elf32_Phdr
        dd	0x1			; p_type
        dd	0x0			; p_offset
        dd	0x8048000			; p_vaddr
        dd	0x8048000			; p_paddr
        dd	1516			; p_filesz
        dd	1516			; p_memsz
        dd	5			; p_flags
        dd	0x1000			; p_align
	; PHT 3
phdr_3:					; Elf32_Phdr
        dd	0x1			; p_type
        dd	0xf14			; p_offset
        dd	0x8049f14			; p_vaddr
        dd	0x8049f14			; p_paddr
        dd	256			; p_filesz
        dd	264			; p_memsz
        dd	6			; p_flags
        dd	0x1000			; p_align
	; PHT 4
phdr_4:					; Elf32_Phdr
        dd	0x2			; p_type
        dd	0xf28			; p_offset
        dd	0x8049f28			; p_vaddr
        dd	0x8049f28			; p_paddr
        dd	200			; p_filesz
        dd	200			; p_memsz
        dd	6			; p_flags
        dd	0x4			; p_align
	; PHT 5
phdr_5:					; Elf32_Phdr
        dd	0x4			; p_type
        dd	0x168			; p_offset
        dd	0x8048168			; p_vaddr
        dd	0x8048168			; p_paddr
        dd	68			; p_filesz
        dd	68			; p_memsz
        dd	4			; p_flags
        dd	0x4			; p_align
	; PHT 6
phdr_6:					; Elf32_Phdr
        dd	0x6474e550			; p_type
        dd	0x4f4			; p_offset
        dd	0x80484f4			; p_vaddr
        dd	0x80484f4			; p_paddr
        dd	52			; p_filesz
        dd	52			; p_memsz
        dd	4			; p_flags
        dd	0x4			; p_align
	; PHT 7
phdr_7:					; Elf32_Phdr
        dd	0x6474e551			; p_type
        dd	0x0			; p_offset
        dd	0x0			; p_vaddr
        dd	0x0			; p_paddr
        dd	0			; p_filesz
        dd	0			; p_memsz
        dd	6			; p_flags
        dd	0x4			; p_align
	; PHT 8
phdr_8:					; Elf32_Phdr
        dd	0x6474e552			; p_type
        dd	0xf14			; p_offset
        dd	0x8049f14			; p_vaddr
        dd	0x8049f14			; p_paddr
        dd	236			; p_filesz
        dd	236			; p_memsz
        dd	4			; p_flags
        dd	0x1			; p_align

        phdrsize	equ	$ - phdr_0

	; Program
	; Disassembly of section 1
.section_1:
.interp:	; 0x08048154
das        
insb       
imul       esp, dword [ds:edx+0x2F], 0x6C2D646C
imul       ebp, dword [ds:esi+0x75], 0x6F732E78
xor        al, byte [cs:eax]


	; Disassembly of section 2
.section_2:
.note.ABI-tag:	; 0x08048168
add        al, 0x00
add        byte [ds:eax], al
adc        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
add        byte [ds:eax], al
inc        edi
dec        esi
push       ebp
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:edx], al
add        byte [ds:eax], al
add        byte [ds:esi], al
add        byte [ds:eax], al
add        byte [ds:edi], cl
add        byte [ds:eax], al
add        byte [ds:eax+eax], al


	; Disassembly of section 3
.section_3:
.note.gnu.build-id:	; 0x08048188
add        al, 0x00
add        byte [ds:eax], al
adc        al, 0x00
add        byte [ds:eax], al
add        eax, dword [ds:eax]
add        byte [ds:eax], al
inc        edi
dec        esi
push       ebp
add        byte [ds:ecx+0x61], ah
jns        0xB76E0186
push       ebx
fidivr     dword [ds:edx+0x16]
mov        ecx, 0x323FB27B
aaa        
rcl        dword [ss:ebp+0x46], 0x4A
add        eax, 0x00000250


	; Disassembly of section 4
.section_4:
.gnu.hash:	; 0x080481ac
add        al, byte [ds:eax]
add        byte [ds:eax], al
add        al, 0x00
add        byte [ds:eax], al
add        dword [ds:eax], eax
add        byte [ds:eax], al
add        eax, 0x00000000
and        byte [ds:eax], al
and        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax+eax], al
add        byte [ds:eax], al
lodsd      
dec        ebx
jecxz      0xB76E018C


	; Disassembly of section 5
.section_5:
.dynsym:	; 0x080481cc
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
sub        dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
adc        al, byte [ds:eax]
add        byte [ds:eax], al
add        dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
and        byte [ds:eax], al
add        byte [ds:eax], al
xor        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
adc        al, byte [ds:eax]
add        byte [ds:eax], al
sbb        al, byte [ds:eax]
add        byte [ds:eax], al
fadd       qword [ss:esp+eax+0x00000408]
add        byte [ds:ecx], dl
add        byte [ds:edi], cl
add        byte [ds:eax], al


	; Disassembly of section 6
.section_6:
.dynstr:	; 0x0804821c
add        byte [ds:edi+0x5F], bl
insd       
outsd      
outsb      
pop        edi
jnc        0xB76E029A
popad      
jc         0xB76E029D
pop        edi
pop        edi
add        byte [ds:ecx+ebp*2+0x62], ch
arpl       word [ds:esi], bp
jnc        0xB76E02A2
add        byte [cs:edi+0x49], bl
dec        edi
pop        edi
jnc        0xB76E02B0
imul       ebp, dword [fs:esi+0x5F], 0x64657375
add        byte [ds:eax+0x72], dh
imul       ebp, dword [ds:esi+0x74], 0x5F5F0066
insb       
imul       esp, dword [ds:edx+0x63], 0x6174735F
jc         0xB76E02CC
pop        edi
insd       
popad      
imul       ebp, dword [ds:esi+0x00], 0x42494C47
inc        ebx
pop        edi
xor        ch, byte [ds:esi]
xor        byte [ds:eax], al


	; Disassembly of section 7
.section_7:
.gnu.version:	; 0x08048268
add        byte [ds:eax], al
add        al, byte [ds:eax]
add        byte [ds:eax], al
add        al, byte [ds:eax]
add        dword [ds:eax], eax


	; Disassembly of section 8
.section_8:
.gnu.version_r:	; 0x08048274
add        dword [ds:eax], eax
add        dword [ds:eax], eax
adc        byte [ds:eax], al
add        byte [ds:eax], al
adc        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
adc        byte [ds:ecx+0x69], ch
or         eax, 0x00020000
inc        edx
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        al, dh


	; Disassembly of section 9
.section_9:
.rel.dyn:	; 0x08048294
lahf       
add        al, 0x08
push       es
add        al, byte [ds:eax]
add        byte [ds:eax], al


	; Disassembly of section 10
.section_10:
.rel.plt:	; 0x0804829c
add        byte [ds:eax+0x01070804], ah
add        byte [ds:eax], al
add        al, 0xA0
add        al, 0x08
pop        es
add        al, byte [ds:eax]
add        byte [ds:eax], cl
mov        al, byte [ds:0x03070804]
add        byte [ds:eax], al


	; Disassembly of section 11
.section_11:
.init:	; 0x080482b4
push       ebx
sub        esp, 0x08
call       0x00000000B76E02BD
pop        ebx
add        ebx, 0x00001D37
mov        eax, dword [ds:ebx-0x00000004]
test       eax, eax
je         0xB76E02D3
call       0x00000000B76E0310
call       0x00000000B76E03C0
call       0x00000000B76E0490
add        esp, 0x08
pop        ebx
ret        


	; Disassembly of section 12
.section_12:
.plt:	; 0x080482f0
push       dword [ds:0x08049FF8]
jmp        dword [ds:0x08049FFC]
add        byte [ds:eax], al
add        byte [ds:eax], al
jmp        dword [ds:0x0804A000]
push       0x00000000
jmp        0xB76E02F0
jmp        dword [ds:0x0804A004]
push       0x00000008
jmp        0xB76E02F0
jmp        dword [ds:0x0804A008]
push       0x00000010
jmp        0xB76E02F0


	; Disassembly of section 13
.section_13:
.text:	; 0x08048330
xor        ebp, ebp
pop        esi
mov        ecx, esp
and        esp, 0xFFFFFFF0
push       eax
push       esp
push       edx
push       0x08048480
push       0x08048410
push       ecx
push       esi
push       0x080483E4
call       0x00000000B76E0320
hlt        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
push       ebp
mov        ebp, esp
push       ebx
sub        esp, 0x04
cmp        byte [ds:0x0804A014], 0x00000000
jne        0xB76E03AF
mov        eax, dword [ds:0x0804A018]
mov        ebx, 0x08049F20
sub        ebx, 0x08049F1C
sar        ebx, 0x02
sub        ebx, 0x01
cmp        eax, ebx
jnc        0xB76E03A8
lea        esi, dword [ds:esi+0x00000000]
add        eax, 0x01
mov        dword [ds:0x0804A018], eax
call       dword [ds:0x08049F1C+eax*4]
mov        eax, dword [ds:0x0804A018]
cmp        eax, ebx
jc         0xB76E0390
mov        byte [ds:0x0804A014], 0x00000001
add        esp, 0x04
pop        ebx
pop        ebp
ret        
lea        esi, dword [ds:esi+0x00]
lea        edi, dword [ds:edi+0x00000000]
push       ebp
mov        ebp, esp
sub        esp, 0x18
mov        eax, dword [ds:0x08049F24]
test       eax, eax
je         0xB76E03E1
mov        eax, 0x00000000
test       eax, eax
je         0xB76E03E1
mov        dword [ss:esp], 0x08049F24
call       eax
leave      
ret        
nop        
push       ebp
mov        ebp, esp
and        esp, 0xFFFFFFF0
sub        esp, 0x10
mov        eax, 0x080484E0
mov        dword [ss:esp], eax
call       0x00000000B76E0300
mov        eax, 0x00000000
leave      
ret        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
push       ebp
push       edi
push       esi
push       ebx
call       0x00000000B76E0482
add        ebx, 0x00001BDB
sub        esp, 0x1C
mov        ebp, dword [ss:esp+0x30]
lea        edi, dword [ds:ebx-0x000000E0]
call       0x00000000B76E02B4
lea        eax, dword [ds:ebx-0x000000E0]
sub        edi, eax
sar        edi, 0x02
test       edi, edi
je         0xB76E0469
xor        esi, esi
lea        esi, dword [ds:esi+0x00000000]
mov        eax, dword [ss:esp+0x38]
mov        dword [ss:esp], ebp
mov        dword [ss:esp+0x08], eax
mov        eax, dword [ss:esp+0x34]
mov        dword [ss:esp+0x04], eax
call       dword [ds:ebx+esi*4-0x000000E0]
add        esi, 0x01
cmp        esi, edi
jne        0xB76E0448
add        esp, 0x1C
pop        ebx
pop        esi
pop        edi
pop        ebp
ret        
jmp        0xB76E0480
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
rep ret    
mov        ebx, dword [ss:esp]
ret        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
nop        
push       ebp
mov        ebp, esp
push       ebx
sub        esp, 0x04
mov        eax, dword [ds:0x08049F14]
cmp        eax, 0xFFFFFFFF
je         0xB76E04B4
mov        ebx, 0x08049F14
nop        
sub        ebx, 0x04
call       eax
mov        eax, dword [ds:ebx]
cmp        eax, 0xFFFFFFFF
jne        0xB76E04A8
add        esp, 0x04
pop        ebx
pop        ebp
ret        
nop        
nop        


	; Disassembly of section 14
.section_14:
.fini:	; 0x080484bc
push       ebx
sub        esp, 0x08
call       0x00000000B76E04C5
pop        ebx
add        ebx, 0x00001B2F
call       0x00000000B76E0360
add        esp, 0x08
pop        ebx
ret        


	; Disassembly of section 15
.section_15:
.rodata:	; 0x080484d8
add        eax, dword [ds:eax]
add        byte [ds:eax], al
add        dword [ds:eax], eax
add        al, byte [ds:eax]
jne        0xB76E0550
imul       ebp, dword [ds:esi+0x66], 0x65746365
and        byte [fs:edx+0x69], ah
outsb      
popad      
jc         0xB76E056A
add        byte [ds:eax], al


	; Disassembly of section 16
.section_16:
.eh_frame_hdr:	; 0x080484f4
add        dword [ds:ebx], ebx
add        edi, dword [ds:ebx]
xor        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, 0xFC000000
std        


	; Disassembly of section 17
.section_17:
.eh_frame:	; 0x08048528
adc        al, 0x00
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:edx+0x52], edi
add        byte [ds:ecx], al
jl         0xB76E053F
add        dword [ds:ebx], ebx
or         al, 0x04
add        al, 0x88
add        dword [ds:eax], eax
add        byte [ds:eax], ah
add        byte [ds:eax], al
add        byte [ds:eax+eax], bl
add        byte [ds:eax], al
test       al, 0xFD


	; Disassembly of section 18
.section_18:
.ctors:	; 0x08048f14


	; Disassembly of section 19
.section_19:
.dtors:	; 0x08048f1c


	; Disassembly of section 20
.section_20:
.jcr:	; 0x08048f24
add        byte [ds:eax], al
add        byte [ds:eax], al


	; Disassembly of section 21
.section_21:
.dynamic:	; 0x08048f28
add        dword [ds:eax], eax
add        byte [ds:eax], al
adc        byte [ds:eax], al
add        byte [ds:eax], al
or         al, 0x00
add        byte [ds:eax], al
mov        ah, 0x82
add        al, 0x08
or         eax, 0xBC000000
test       byte [ds:eax+ecx], al
cmc        


	; Disassembly of section 22
.section_22:
.got:	; 0x08048ff0
add        byte [ds:eax], al
add        byte [ds:eax], al


	; Disassembly of section 23
.section_23:
.got.plt:	; 0x08048ff4
sub        byte [ds:edi+0x00000804], bl
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
push       es
add        dword [ds:eax+ecx], 0x16
add        dword [ds:eax+ecx], 0x26
add        dword [ds:eax+ecx], 0x00000000


	; Disassembly of section 24
.section_24:
.data:	; 0x0804900c
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al


	; Disassembly of section 25
.section_25:
.bss:	; 0x08049014
inc        edi
inc        ebx
inc        ebx
cmp        ah, byte [ds:eax]
sub        byte [ss:ebp+0x62], dl


	; Disassembly of section 26
.section_26:
.comment:	; 0x08049014
inc        edi
inc        ebx
inc        ebx
cmp        ah, byte [ds:eax]
sub        byte [ss:ebp+0x62], dl
jne        0xB76E108C
je         0xB76E1095
das        
dec        esp
imul       ebp, dword [ds:esi+0x61], 0x34206F72
xor        dword [cs:0x75627539], ebp
outsb      
je         0xB76E10AA
xor        ebp, dword [ds:ecx]
and        byte [ds:esi+ebp], dh
xor        dword [cs:eax], eax


	; Disassembly of section 27
.section_27:
.shstrtab:	; 0x0804903e
add        byte [ds:esi], ch
jnc        0xB76E10BB
insd       
je         0xB76E10A6
bound      eax, dword [ds:eax]
jnc        0xB76E10BE
jc         0xB76E10C0
popad      
bound      eax, dword [ds:eax]
jnc        0xB76E10BA
jnc        0xB76E10C8
jc         0xB76E10CA
popad      
bound      eax, dword [ds:eax]
imul       ebp, dword [cs:esi+0x74], 0x00707265
outsb      
outsd      
je         0xB76E10CB
inc        ecx
inc        edx
dec        ecx
sub        eax, 0x00676174
outsb      
outsd      
je         0xB76E10D9
outsb      
jne        0xB76E10A7
bound      esi, dword [ss:ebp+0x69]
insb       
sub        eax, 0x2E006469
outsb      
jne        0xB76E10B5
push       0x00687361
jns        0xB76E10FE
jnc        0xB76E110B
insd       
add        byte [ds:esi], ch
jns        0xB76E1106
jnc        0xB76E110E
jc         0xB76E109C
outsb      
jne        0xB76E10CF
jbe        0xB76E1108
jc         0xB76E1118
imul       ebp, dword [ds:edi+0x6E], 0x6E672E00
jne        0xB76E10DC
jbe        0xB76E1115
jc         0xB76E1125
imul       ebp, dword [ds:edi+0x6E], 0x2E00725F
jc         0xB76E1120
insb       
jns        0xB76E112E
add        byte [ds:esi], ch
jc         0xB76E1129
insb       
jo         0xB76E1134
je         0xB76E10CA
imul       ebp, dword [cs:esi+0x69], 0x742E0074
js         0xB76E1149
add        byte [ds:esi], ch
imul       bp, word [ds:esi+0x69], 0x2E00
jc         0xB76E114E
popad      
je         0xB76E1144
add        byte [ds:esi], ch
push       0x6172665F
insd       
pop        edi
push       0x2E007264
push       0x6172665F
insd       
add        byte [gs:esi], ch
arpl       word [ds:edi+ebp*2+0x72], si
jnc        0xB76E1103
je         0xB76E1176
jc         0xB76E117C
add        byte [ds:esi], ch
push       0x00000063
jc         0xB76E110F
jns        0xB76E1181
popad      
insd       
imul       esp, dword [ds:ebx+0x00], 0x746F672E
add        byte [ds:esi], ch
outsd      
je         0xB76E1150
jo         0xB76E1190
je         0xB76E1126
popad      
je         0xB76E118C
add        byte [ds:esi], ch
bound      esi, dword [ds:ebx+0x73]
add        byte [ds:esi], ch
arpl       word [ds:edi+0x6D], bp
insd       
outsb      
je         0xB76E113A


	; Disassembly of section 28
.section_28:
.symtab:	; 0x080495ec
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
push       esp
add        dword [ds:eax+ecx], 0x00000000
add        eax, dword [ds:eax]
add        dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
push       0x00080481
add        byte [ds:eax], al
add        byte [ds:ebx], al
add        byte [ds:edx], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax+0x00080481], cl
add        byte [ds:eax], al
add        byte [ds:ebx], al
add        byte [ds:ebx], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:ecx+eax*4+0x00000804], ch
add        byte [ds:eax], al
add        eax, dword [ds:eax]
add        al, 0x00
add        byte [ds:eax], al
add        byte [ds:eax], al
int3       
add        dword [ds:eax+ecx], 0x00000000
add        eax, dword [ds:eax]
add        eax, 0x00000000
add        byte [ds:edx+eax*4], bl
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
push       es
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax-0x7E], ch
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
pop        es
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:edx+eax*4+0x04], dh
or         byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:ebx], al
add        byte [ds:eax], cl
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:edx+eax*4+0x00000804], dl
add        byte [ds:eax], al
add        eax, dword [ds:eax]
or         dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
pushfd     
add        byte [ds:eax+ecx], 0x00000000
add        byte [ds:eax], al
add        byte [ds:ebx], al
add        byte [ds:edx], cl
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:edx+eax*4+0x00000804], dh
add        byte [ds:eax], al
add        eax, dword [ds:eax]
or         eax, dword [ds:eax]
add        byte [ds:eax], al
add        byte [ds:eax], al
lock add   byte [ds:eax+ecx], 0x00000000
add        byte [ds:eax], al
add        byte [ds:ebx], al
add        byte [ds:eax+eax], cl
add        byte [ds:eax], al
add        byte [ds:eax], al
xor        byte [ds:ebx+0x00000804], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
or         eax, 0x00000000
add        byte [ss:esp+eax*4+0x00000804], bh
add        byte [ds:eax], al
add        eax, dword [ds:eax]
push       cs
add        byte [ds:eax], al
add        byte [ds:eax], al
add        al, bl
test       byte [ds:eax+ecx], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
sldt       word [ds:eax]
add        byte [ds:eax], al
add        ah, dh
test       byte [ds:eax+ecx], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
adc        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
sub        byte [ss:ebp+0x00000804], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
adc        dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
adc        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
adc        al, byte [ds:eax]
add        byte [ds:eax], al
add        byte [ds:eax], al
sbb        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
adc        eax, dword [ds:eax]
add        byte [ds:eax], al
add        byte [ds:eax], al
and        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
adc        al, 0x00
add        byte [ds:eax], al
add        byte [ds:eax], al
sub        byte [ds:edi+0x00000804], bl
add        byte [ds:eax], al
add        eax, dword [ds:eax]
adc        eax, 0x00000000
add        al, dh
lahf       
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
push       ss
add        byte [ds:eax], al
add        byte [ds:eax], al
add        ah, dh
lahf       
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
pop        ss
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], cl
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
sbb        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
adc        al, 0xA0
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
sbb        dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        eax, dword [ds:eax]
sbb        al, byte [ds:eax]
add        dword [ds:eax], eax
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        al, 0x00
int1       
dec        dword [ds:eax+eax]
add        byte [ds:eax], al
adc        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
adc        al, byte [ds:eax]
sbb        al, byte [ds:eax]
add        byte [ds:eax], al
sbb        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
adc        eax, dword [ds:eax]
sub        byte [ds:eax], al
add        byte [ds:eax], al
and        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
adc        al, 0x00
xor        eax, 0x60000000
add        dword [ds:eax+ecx], 0x00000000
add        byte [ds:eax], al
add        byte [ds:edx], al
add        byte [ds:0x00004B00], cl
add        byte [ds:eax], dl
add        al, 0x08
add        dword [ds:eax], eax
add        byte [ds:eax], al
add        dword [ds:eax], eax
sbb        dword [ds:eax], eax
pop        edx
add        byte [ds:eax], al
add        byte [ds:eax], bl
mov        al, byte [ds:0x00040804]
add        byte [ds:eax], al
add        dword [ds:eax], eax
sbb        dword [ds:eax], eax
push       0xC0000000
add        dword [ds:eax+ecx], 0x00000000
add        byte [ds:eax], al
add        byte [ds:edx], al
add        byte [ds:0x00000100], cl
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax+eax], al
int1       
push       dword [ds:eax+eax+0x00]
add        byte [ds:eax], bl
lahf       
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
adc        al, byte [ds:eax]
add        dword [ds:eax], 0x85E80000
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
adc        dword [ds:eax], eax
pop        dword [ds:eax]
add        byte [ds:eax], al
and        al, 0x9F
add        al, 0x08
add        byte [ds:eax], al
add        byte [ds:eax], al
add        dword [ds:eax], eax
adc        al, 0x00
wait       
add        byte [ds:eax], al
add        byte [ds:eax+0x00080484], dl
add        byte [ds:eax], al
add        byte [ds:edx], al
add        byte [ds:0x0000B100], cl
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax], al
add        byte [ds:eax+eax], al
int1       


	; Disassembly of section 29
.section_29:
.strtab:	; 0x080499fc
add        byte [ds:ebx+0x72], ah
je         0xB76E1A74
je         0xB76E1A78
arpl       word [cs:eax], ax
pop        edi
pop        edi
inc        ebx
push       esp
dec        edi
push       edx
pop        edi
dec        esp
dec        ecx
push       ebx
push       esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
inc        esp
push       esp
dec        edi
push       edx
pop        edi
dec        esp
dec        ecx
push       ebx
push       esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
dec        edx
inc        ebx
push       edx
pop        edi
dec        esp
dec        ecx
push       ebx
push       esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
outsd      
pop        edi
insb       
outsd      
bound      esp, dword [ds:ecx+0x6C]
pop        edi
je         0xB76E1AAF
jc         0xB76E1AB5
pop        edi
popad      
jne        0xB76E1ABE
add        byte [ds:ebx+0x6F], ah
insd       
jo         0xB76E1AB8
je         0xB76E1AB4
xor        byte [fs:eax], bh
add        byte [ss:esp+esi*2+0x6F], ah
jc         0xB76E1ABA
imul       esp, dword [ds:eax+edi*2+0x2E], 0x38383036
add        byte [ds:esi+0x72], ah
popad      
insd       
pop        edi
jne        0xB76E1ADA
insd       
jns        0xB76E1A70
pop        edi
pop        edi
inc        ebx
push       esp
dec        edi
push       edx
pop        edi
inc        ebp
dec        esi
inc        esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
inc        esi
push       edx
inc        ecx
dec        ebp
inc        ebp
pop        edi
inc        ebp
dec        esi
inc        esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
dec        edx
inc        ebx
push       edx
pop        edi
inc        ebp
dec        esi
inc        esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
outsd      
pop        edi
insb       
outsd      
bound      esp, dword [ds:ecx+0x6C]
pop        edi
arpl       word [ds:edi+ebp*2+0x72], si
jnc        0xB76E1B08
popad      
jne        0xB76E1B24
add        byte [ss:ebp+0x6E], dh
imul       ebp, dword [ds:esi+0x66], 0x65746365
arpl       word [fs:eax], ax
pop        edi
pop        edi
imul       ebp, dword [ds:esi+0x69], 0x72615F74
jc         0xB76E1B26
jns        0xB76E1B26
outsb      
add        byte [fs:edi+0x44], bl
pop        ecx
dec        esi
inc        ecx
dec        ebp
dec        ecx
inc        ebx
add        byte [ds:edi+0x5F], bl
imul       ebp, dword [ds:esi+0x69], 0x72615F74
jc         0xB76E1B40
jns        0xB76E1B40
jnc        0xB76E1B57
popad      
jc         0xB76E1B5A
add        byte [ds:edi+0x47], bl
dec        esp
dec        edi
inc        edx
inc        ecx
dec        esp
pop        edi
dec        edi
inc        esi
inc        esi
push       ebx
inc        ebp
push       esp
pop        edi
push       esp
inc        ecx
inc        edx
dec        esp
inc        ebp
pop        edi
add        byte [ds:edi+0x5F], bl
insb       
imul       esp, dword [ds:edx+0x63], 0x7573635F
pop        edi
imul       bp, word [ds:esi+0x69], 0x5F00
pop        edi
imul       esi, dword [ds:esi], 0x672E3638
je         0xB76E1B77
jo         0xB76E1B7D
pop        edi
je         0xB76E1B85
jne        0xB76E1B8D
imul       ebp, dword [ds:esi], 0x62
js         0xB76E1B24
popad      
je         0xB76E1B89
pop        edi
jnc        0xB76E1B9F
popad      
jc         0xB76E1BA2
add        byte [ds:eax+0x72], dh
imul       ebp, dword [ds:esi+0x74], 0x47404066
dec        esp
dec        ecx
inc        edx
inc        ebx
pop        edi
xor        ch, byte [ds:esi]
xor        byte [ds:eax], al
pop        edi
popad      
je         0xB76E1BA8
add        byte [ds:edi+0x66], bl
imul       ebp, dword [ds:esi+0x69], 0x445F5F00
push       esp
dec        edi
push       edx
pop        edi
inc        ebp
dec        esi
inc        esp
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
popad      
je         0xB76E1BC2
pop        edi
jnc        0xB76E1BD8
popad      
jc         0xB76E1BDB
add        byte [ds:edi+0x5F], bl
insd       
outsd      
outsb      
pop        edi
jnc        0xB76E1BE5
popad      
jc         0xB76E1BE8
pop        edi
pop        edi
add        byte [ds:edi+0x5F], bl
jnc        0xB76E1BEB
pop        edi
push       0x6C646E61
add        byte [gs:edi+0x49], bl
dec        edi
pop        edi
jnc        0xB76E1BFE
imul       ebp, dword [fs:esi+0x5F], 0x64657375
add        byte [ds:edi+0x5F], bl
insb       
imul       esp, dword [ds:edx+0x63], 0x6174735F
jc         0xB76E1C13
pop        edi
insd       
popad      
imul       ebp, dword [ds:esi+0x40], 0x494C4740
inc        edx
inc        ebx
pop        edi
xor        ch, byte [ds:esi]
xor        byte [ds:eax], al
pop        edi
pop        edi
insb       
imul       esp, dword [ds:edx+0x63], 0x7573635F
pop        edi
imul       ebp, dword [ds:esi+0x69], 0x655F0074
outsb      
add        byte [fs:edi+0x73], bl
je         0xB76E1C2A
jc         0xB76E1C3F
add        byte [ds:edi+0x66], bl
jo         0xB76E1C2F
push       0x5F5F0077
bound      esi, dword [ds:ebx+0x73]
pop        edi
jnc        0xB76E1C4F
popad      
jc         0xB76E1C52
add        byte [ss:ebp+0x61], ch
imul       ebp, dword [ds:esi+0x00], 0x5F764A5F
push       edx
imul       esi, dword [gs:bp+di+0x74], 0x6C437265
popad      
jnc        0xB76E1C68
jnc        0xB76E1BF8
pop        edi
imul       ebp, dword [ds:esi+0x69], 0x00000074



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
        dd	0x1b		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048154	; sh_addr Section virtual addr at execution
        dd	0x154		; sh_offset Section file offset
        dd	0x13		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x1		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_2:
        dd	0x23		; sh_name Section name (string tbl index)
        dd	0x7		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048168	; sh_addr Section virtual addr at execution
        dd	0x168		; sh_offset Section file offset
        dd	0x20		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_3:
        dd	0x31		; sh_name Section name (string tbl index)
        dd	0x7		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048188	; sh_addr Section virtual addr at execution
        dd	0x188		; sh_offset Section file offset
        dd	0x24		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_4:
        dd	0x44		; sh_name Section name (string tbl index)
        dd	0x6ffffff6		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x080481ac	; sh_addr Section virtual addr at execution
        dd	0x1ac		; sh_offset Section file offset
        dd	0x20		; sh_size Section size in bytes
        dd	0x5		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x4		; sh_entsize Entry size if section holds table


sht_5:
        dd	0x4e		; sh_name Section name (string tbl index)
        dd	0xb		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x080481cc	; sh_addr Section virtual addr at execution
        dd	0x1cc		; sh_offset Section file offset
        dd	0x50		; sh_size Section size in bytes
        dd	0x6		; sh_link Link to another section
        dd	0x1		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x10		; sh_entsize Entry size if section holds table


sht_6:
        dd	0x56		; sh_name Section name (string tbl index)
        dd	0x3		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x0804821c	; sh_addr Section virtual addr at execution
        dd	0x21c		; sh_offset Section file offset
        dd	0x4c		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x1		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_7:
        dd	0x5e		; sh_name Section name (string tbl index)
        dd	0x6fffffff		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048268	; sh_addr Section virtual addr at execution
        dd	0x268		; sh_offset Section file offset
        dd	0xa		; sh_size Section size in bytes
        dd	0x5		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x2		; sh_addralign Section alignment
        dd	0x2		; sh_entsize Entry size if section holds table


sht_8:
        dd	0x6b		; sh_name Section name (string tbl index)
        dd	0x6ffffffe		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048274	; sh_addr Section virtual addr at execution
        dd	0x274		; sh_offset Section file offset
        dd	0x20		; sh_size Section size in bytes
        dd	0x6		; sh_link Link to another section
        dd	0x1		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_9:
        dd	0x7a		; sh_name Section name (string tbl index)
        dd	0x9		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048294	; sh_addr Section virtual addr at execution
        dd	0x294		; sh_offset Section file offset
        dd	0x8		; sh_size Section size in bytes
        dd	0x5		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x8		; sh_entsize Entry size if section holds table


sht_10:
        dd	0x83		; sh_name Section name (string tbl index)
        dd	0x9		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x0804829c	; sh_addr Section virtual addr at execution
        dd	0x29c		; sh_offset Section file offset
        dd	0x18		; sh_size Section size in bytes
        dd	0x5		; sh_link Link to another section
        dd	0xc		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x8		; sh_entsize Entry size if section holds table


sht_11:
        dd	0x8c		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x6		; sh_flags Section flags
        dd	0x080482b4	; sh_addr Section virtual addr at execution
        dd	0x2b4		; sh_offset Section file offset
        dd	0x2e		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_12:
        dd	0x87		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x6		; sh_flags Section flags
        dd	0x080482f0	; sh_addr Section virtual addr at execution
        dd	0x2f0		; sh_offset Section file offset
        dd	0x40		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x10		; sh_addralign Section alignment
        dd	0x4		; sh_entsize Entry size if section holds table


sht_13:
        dd	0x92		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x6		; sh_flags Section flags
        dd	0x08048330	; sh_addr Section virtual addr at execution
        dd	0x330		; sh_offset Section file offset
        dd	0x18c		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x10		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_14:
        dd	0x98		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x6		; sh_flags Section flags
        dd	0x080484bc	; sh_addr Section virtual addr at execution
        dd	0x4bc		; sh_offset Section file offset
        dd	0x1a		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_15:
        dd	0x9e		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x080484d8	; sh_addr Section virtual addr at execution
        dd	0x4d8		; sh_offset Section file offset
        dd	0x1a		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_16:
        dd	0xa6		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x080484f4	; sh_addr Section virtual addr at execution
        dd	0x4f4		; sh_offset Section file offset
        dd	0x34		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_17:
        dd	0xb4		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x2		; sh_flags Section flags
        dd	0x08048528	; sh_addr Section virtual addr at execution
        dd	0x528		; sh_offset Section file offset
        dd	0xc4		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_18:
        dd	0xbe		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x08049f14	; sh_addr Section virtual addr at execution
        dd	0xf14		; sh_offset Section file offset
        dd	0x8		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_19:
        dd	0xc5		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x08049f1c	; sh_addr Section virtual addr at execution
        dd	0xf1c		; sh_offset Section file offset
        dd	0x8		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_20:
        dd	0xcc		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x08049f24	; sh_addr Section virtual addr at execution
        dd	0xf24		; sh_offset Section file offset
        dd	0x4		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_21:
        dd	0xd1		; sh_name Section name (string tbl index)
        dd	0x6		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x08049f28	; sh_addr Section virtual addr at execution
        dd	0xf28		; sh_offset Section file offset
        dd	0xc8		; sh_size Section size in bytes
        dd	0x6		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x8		; sh_entsize Entry size if section holds table


sht_22:
        dd	0xda		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x08049ff0	; sh_addr Section virtual addr at execution
        dd	0xff0		; sh_offset Section file offset
        dd	0x4		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x4		; sh_entsize Entry size if section holds table


sht_23:
        dd	0xdf		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x08049ff4	; sh_addr Section virtual addr at execution
        dd	0xff4		; sh_offset Section file offset
        dd	0x18		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x4		; sh_entsize Entry size if section holds table


sht_24:
        dd	0xe8		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x0804a00c	; sh_addr Section virtual addr at execution
        dd	0x100c		; sh_offset Section file offset
        dd	0x8		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_25:
        dd	0xee		; sh_name Section name (string tbl index)
        dd	0x8		; sh_type Section type
        dd	0x3		; sh_flags Section flags
        dd	0x0804a014	; sh_addr Section virtual addr at execution
        dd	0x1014		; sh_offset Section file offset
        dd	0x8		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_26:
        dd	0xf3		; sh_name Section name (string tbl index)
        dd	0x1		; sh_type Section type
        dd	0x30		; sh_flags Section flags
        dd	0x00000000	; sh_addr Section virtual addr at execution
        dd	0x1014		; sh_offset Section file offset
        dd	0x2a		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x1		; sh_addralign Section alignment
        dd	0x1		; sh_entsize Entry size if section holds table


sht_27:
        dd	0x11		; sh_name Section name (string tbl index)
        dd	0x3		; sh_type Section type
        dd	0x0		; sh_flags Section flags
        dd	0x00000000	; sh_addr Section virtual addr at execution
        dd	0x103e		; sh_offset Section file offset
        dd	0xfc		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x1		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table


sht_28:
        dd	0x1		; sh_name Section name (string tbl index)
        dd	0x2		; sh_type Section type
        dd	0x0		; sh_flags Section flags
        dd	0x00000000	; sh_addr Section virtual addr at execution
        dd	0x15ec		; sh_offset Section file offset
        dd	0x410		; sh_size Section size in bytes
        dd	0x1d		; sh_link Link to another section
        dd	0x2d		; sh_info Additional section information
        dd	0x4		; sh_addralign Section alignment
        dd	0x10		; sh_entsize Entry size if section holds table


sht_29:
        dd	0x9		; sh_name Section name (string tbl index)
        dd	0x3		; sh_type Section type
        dd	0x0		; sh_flags Section flags
        dd	0x00000000	; sh_addr Section virtual addr at execution
        dd	0x19fc		; sh_offset Section file offset
        dd	0x202		; sh_size Section size in bytes
        dd	0x0		; sh_link Link to another section
        dd	0x0		; sh_info Additional section information
        dd	0x1		; sh_addralign Section alignment
        dd	0x0		; sh_entsize Entry size if section holds table



