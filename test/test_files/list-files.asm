; backdoor (32 bit)
; By i4k
;
; $ Makefile
; all:
;   nasm -f bin -o backdoor.o backdoor.asm -l backdoor.l
;

%include "inc/syscall.inc.asm"

%define         PT_LOAD         01
%define         O_RDWR          2
%define         LISTEN          4
%define         SIGKILL         9
%define         ELFMAG          0x464C457F

%macro  prologue 0
    push    ebp
    mov     ebp,esp
%endmacro

%macro  prologue 1
    push    ebp
    mov     ebp,esp
    sub     esp,%1
%endmacro

%macro epilogue 0
    mov esp, ebp
    pop ebp
%endmacro

global _start

section .text

_start:
    prologue

    ; reserva espaço para duas variáveis locais
    ; [esp] = total de bytes lidos por getdents
    ; [esp+4] = offset da estrutura dirent
    sub esp, 0x08
    
    mov ecx, [ebp+4] ; argc
    mov ebx, 1
    cmp ecx, ebx
    je use_cur_dir
    
use_cmd_dir:    
    mov edx, [ebp+8]
    push edx
    call stringlen
    pop edx
    
    add edx, eax
    jmp list_dir
    
use_cur_dir:
	    push dword 0x0000002e
	    mov edx, esp
	    jmp list_dir
    
list_dir:    
    push DWORD edx
    call print
    pop edx
    
    push edx
    push word 0x000a
    push byte 0x3a
    call print
    add esp, 4
    
    pop edx

    ; Abre o diretório atual
    push dword edx
    call opendir

    push eax    ; eax = fd
    call getdents

    mov ebx, -1
    cmp ah, bh
    jz getdents_error

    mov [esp], eax          ; armazena o total de bytes de getdents
    mov DWORD [esp+4], 0x00 ; contador para o loop dos diretorios

    xor eax, eax
    mov ebx, dirent
loop_next_file:
    add ebx, eax
    mov edx, ebx
    add ebx, 0x0A           ; posição de d_name[]

    ; salva edx e eax na stack
    ; pois print vai sobrescre-los
    push edx
    push eax

    ; printa o nome do arquivo/diretorio
    push ebx
    call print

    pop ebx

    ; printa quebra de linha
    push dword 0x0000000a
    push esp
    call print
    
    add esp, 8              ; descarta os parametro da stack

    ; restaura eax e edx
    pop eax
    pop edx

    mov ebx, edx
    xor eax, eax
    xor ecx, ecx
    mov ax, [edx+8]
    mov cx, [esp+4]
    add ecx, eax
    mov edx, [esp]
    mov [esp+4], ecx
    cmp ecx, edx
    jl loop_next_file

    call exit

    epilogue

;
; banner
;
help:
    push usage_str
    call print
    call exit

;
; unsigned int stringlen(char* str);
stringlen:
    prologue

    mov ecx, [ebp+8]    ; primeiro parametro
    xor eax, eax        ; contador

stringlen_loopStart:
    xor dx, dx
    mov dl, byte [ecx+eax]
    inc eax

    cmp dl, 0x0 ; null byte
    jne stringlen_loopStart
stringlen_loopEnd:
    epilogue
    ret

; void print(char* msg)
print:
    prologue

    mov ecx, [ebp+8]
    push ecx
    call stringlen
    add esp, 4      ; descarta parametro

    mov edx, eax    ; tamanho da string em eax
    xor ebx, ebx
    xor eax, eax
    mov ebx, 1  ; standard output
    mov al, sys_write
    int 0x80

    epilogue
    ret

; int opendir(char* path)
opendir:
    prologue

    mov ebx, [ebp+8]
    xor  eax, eax
    mov   al, sys_open
    xor  ecx, ecx           ;O_RDONLY
    xor  edx, edx           ;
    int  0x80

    epilogue
    ret

; int getdents(int fd)
getdents:
    prologue

    mov ebx, [ebp+8]
    xor  eax, eax
    mov   al, sys_getdents
    mov  ecx, dirent
    mov  edx, 0x10000
    int  0x80

    epilogue
    ret

getdents_error:
        pop edx
        pop edx

        push dword 0x00212121
push dword 0x4f4d4120
push dword 0x45542055
push dword 0x45202c41
push dword 0x4c4c4549
push dword 0x52424147

        
        push esp
    call print
        pop edx
        pop edx
        pop edx
    call exit

exit:
    xor eax, eax
    inc eax
    int 0x80
    ret
