#ifndef ELF_OBJECT_H
#define ELF_OBJECT_H

#include <elf.h>
#include <link.h>
#include <errno.h>
#include <sys/stat.h>
#include "types.h"

#define GET_ATTR_NAME(attr) attr != NULL ? (attr->name) : "UNKNOWN"
#define GET_ATTR_DESC(attr) attr != NULL ? (attr->desc) : "UNKNOWN"

#define GET_SECTION_NAME(obj, header, sections, sec_idx) (char*) (obj->mem + sections[header->e_shstrndx].sh_offset + sections[sec_idx].sh_name)
#define MALELF_MAP_ELF(obj) do {\
  assert(obj->mem != NULL);\
  obj->elf.elfh = (ElfW(Ehdr)*) obj->mem;\
  assert(obj->elf.elfh != NULL); \
  assert((off_t)obj->elf.elfh->e_phoff < obj->st_info.st_size); \
  assert((off_t)obj->elf.elfh->e_shoff < obj->st_info.st_size);         \
  obj->elf.elfp = (ElfW(Phdr)*) (obj->mem + obj->elf.elfh->e_phoff);\
  obj->elf.elfs = (ElfW(Shdr)*) (obj->mem + obj->elf.elfh->e_shoff);\
  } while(0)

typedef enum {
  ALLOC_MMAP = 0,
  ALLOC_MALLOC
} alloc_type_t;

union malelf_dword {
    unsigned long int long_val;
    unsigned char char_val[4];
};

typedef struct {
  ElfW(Ehdr) *elfh;
  ElfW(Phdr) *elfp;
  ElfW(Shdr) *elfs;
} malelf_elf_t;

typedef struct {
  char* fname;
  int fd;
  struct stat st_info;
  _u8* mem;
  malelf_elf_t elf;
  _u8 is_readonly;
  alloc_type_t alloc_type;
} malelf_object;

typedef struct {
  char* name;
  _u32 val;
  char* desc;
} malelf_elf_attr;

typedef struct {
  const char* name;
  const char* data_fname;
} malelf_add_section_t;

extern malelf_elf_attr elf_object_types[];
extern malelf_elf_attr elf_machine[];
extern malelf_elf_attr elf_section_types[];
extern malelf_elf_attr elf_segment_types[];
extern malelf_elf_attr elf_segment_flags[];

extern void malelf_init_object(malelf_object*);
extern void read_elf_file(malelf_object*);
extern void create_elf_file(malelf_object*);
extern _u8 copy_malelf_object_raw(malelf_object*, malelf_object*);
extern _i32 malelf_open(malelf_object* obj, char* filename, int flags);
extern _i32 malelf_openr(malelf_object* obj, char* filename);
extern _i32 malelf_openw(malelf_object* obj, char* filename);
extern _u32 malelf_close(malelf_object* obj);
extern _u8 malelf_check_elf(malelf_object* obj);
extern _u8 malelf_add_section(malelf_object* i, malelf_object* o, malelf_add_section_t opt);

extern malelf_elf_attr* get_header_type(ElfW(Half) etype);
extern malelf_elf_attr* get_section_type(ElfW(Half) stype);
extern malelf_elf_attr* get_machine(ElfW(Half) emach);
extern malelf_elf_attr* get_segment_type(ElfW(Word) seg);

extern void pretty_print_elf_header(ElfW(Ehdr)*);
extern void pretty_print_pht(ElfW(Ehdr)*, ElfW(Phdr)*);
extern void pretty_print_sht(malelf_object*,ElfW(Ehdr)*, ElfW(Shdr)*);
extern void pretty_print_strtab(malelf_object*,ElfW(Ehdr)*, ElfW(Shdr)*);
#endif
