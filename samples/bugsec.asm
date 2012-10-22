BITS 32

        push ebp
        mov ebp,esp

        push dword 0x00455453
        push word 0x4554
        
        mov ecx, esp
        mov edx, 5
        mov ebx, 1
        mov eax, 4
        int 0x80

        mov esp, ebp
        pop ebp