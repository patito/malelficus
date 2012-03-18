#ifndef ELF_OBJECT_H
#define ELF_OBJECT_H

#include <elf.h>
#include <link.h>
#include <sys/stat.h>
#include "types.h"

typedef struct {
  int fd;
  char* fname;            /* filename */
  struct stat st_info;    /* stat information */
  _u8* mem;               /* memory mapped */
  ElfW(Ehdr) *elfh;       /* pointer to elf header */
  ElfW(Phdr) *elfp;       /* pointer to program header table */
  ElfW(Shdr) *elfs;       /* pointer to section header table */
} elf_object;

typedef struct {
  char* name;
  _u16 val;
  char* desc;
} elf_attr;

#define N_OBJTYPES 5
#define N_MACHINES 8

extern elf_attr object_types[N_OBJTYPES];
extern elf_attr elf_machine[N_MACHINES];

extern void init_elf_object(elf_object*);
extern _u8 copy_elf_object(elf_object*, elf_object*);
#endif
