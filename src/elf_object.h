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
#define N_SHTYPES 12

extern elf_attr object_types[N_OBJTYPES];
extern elf_attr elf_machine[N_MACHINES];
extern elf_attr elf_shtypes[N_SHTYPES];

extern void init_elf_object(elf_object*);
extern _u8 copy_elf_object(elf_object*, elf_object*);
extern void pretty_print_elf_header2(ElfW(Ehdr)*) __attribute__((deprecated));
extern void pretty_print_elf_header(ElfW(Ehdr)*);
extern void pretty_print_pht(ElfW(Ehdr)*, ElfW(Phdr)*);
extern void pretty_print_sht(elf_object*,ElfW(Ehdr)*, ElfW(Shdr)*);
extern void pretty_print_strtab(elf_object*,ElfW(Ehdr)*, ElfW(Shdr)*);
#endif
