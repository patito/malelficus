#ifndef SHELLCODE_H
#define SHELLCODE_H

extern int shellcode_create_c(FILE* fd_o, int in_size, FILE* fd_i, unsigned long int original_entry_point);
extern int shellcode_create_malelficus(FILE* fd_o, int in_size, FILE* fd_i, unsigned long int original_entry_point, unsigned long int magic_bytes);

#endif
