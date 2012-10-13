#ifndef SHELLCODE_H
#define SHELLCODE_H

extern int shellcode_create(FILE* fd_o, int in_size, FILE* fd_i, unsigned long int original_entry_point);

#endif
