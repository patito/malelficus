	BITS 32

	mov edx,25
	push dword 0x0000000a
	push dword 0x21212120
	push dword 0x4f4d4120
	push dword 0x45542055
	push dword 0x45202c41
	push dword 0x4c4c4549
	push dword 0x52424147
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

