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

extern void init_elf_object(elf_object*);
extern _u8 copy_elf_object(elf_object*, elf_object*);
#endif
