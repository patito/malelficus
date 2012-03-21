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
  _u32 val;
  char* desc;
} elf_attr;

extern elf_attr elf_object_types[];
extern elf_attr elf_machine[];
extern elf_attr elf_section_types[];
extern elf_attr elf_segment_types[];
extern elf_attr elf_segment_flags[];

extern void init_elf_object(elf_object*);
extern _u8 copy_elf_object(elf_object*, elf_object*);

extern elf_attr* get_header_type(ElfW(Half) etype);
extern elf_attr* get_section_type(ElfW(Half) stype);
extern elf_attr* get_machine(ElfW(Half) emach);
extern elf_attr* get_segment_type(ElfW(Word) seg);

#define GET_ATTR_NAME(attr) attr != NULL ? (attr->name) : "UNKNOWN"
#define GET_ATTR_DESC(attr) attr != NULL ? (attr->desc) : "UNKNOWN"

extern void pretty_print_elf_header2(ElfW(Ehdr)*) __attribute__((deprecated));
extern void pretty_print_elf_header(ElfW(Ehdr)*);
extern void pretty_print_pht(ElfW(Ehdr)*, ElfW(Phdr)*);
extern void pretty_print_pht2(ElfW(Ehdr)*, ElfW(Phdr)*);
extern void pretty_print_sht(elf_object*,ElfW(Ehdr)*, ElfW(Shdr)*);
extern void pretty_print_strtab(elf_object*,ElfW(Ehdr)*, ElfW(Shdr)*);
#endif
