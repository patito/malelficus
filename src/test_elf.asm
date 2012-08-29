BITS 32

SECTION text
global _start

_start:
    push dword 0x41414141
    mov edx, 4
    mov ecx, esp
    mov ebx, 1
    mov eax, 4
    int 0x80

    mov ebx, 0
    mov eax, 1
    int 0x80
