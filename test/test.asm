;; nasm example
    
    section .text
    global _start
    
_start:
    mov edx, 8
    mov ecx, message
    mov ebx, 1
    mov eax, 4
    int 0x80
    
    mov ebx, 0
    mov eax, 1
    int 0x80
    
message:
    db 'hacked',10,0

