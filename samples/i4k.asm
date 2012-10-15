	BITS 32

	mov edx,25
	push dword 0x00737563
	push dword 0x69464c45
	push dword 0x6c616d20
	push dword 0x79622064
	push dword 0x65746365
	push word 0x666e
	push byte 0x69
	mov ecx, esp
	mov ebx,1
	mov eax,4
	int	0x80

        pop edx
        pop edx
        pop edx
        pop edx
        pop edx
        pop edx
        pop edx

        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx

	;; mov eax, 0x08048580
	;; jmp eax
