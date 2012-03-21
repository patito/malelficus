#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <assert.h>

typedef uint8_t _u8;
typedef uint16_t _u16;
typedef uint32_t _u32;

typedef struct {
  char* name;
  _u16 val;
  char* desc;
} elf_attr;

#define N_OBJTYPES 5

/**
 * Object file types
 * see ELF Format Specification for more details
 */
elf_attr object_types[N_OBJTYPES] = {
  {"ET_NONE", ET_NONE, "No file type"},
  {"ET_REL", ET_REL, "Relocatable file"},
  {"ET_EXEC", ET_EXEC, "Executable file"},
  {"ET_DYN", ET_DYN, "Shared Object file"},
  {"ET_CORE", ET_CORE, "Core file"}
};

#define N_MACHINES 8

/**
 * Possible target machines
 */
elf_attr elf_machine[N_MACHINES] = {
  { "EM_NONE", EM_NONE, "No machine"},
  { "EM_M32", EM_M32, "AT&T WE 32100"},
  { "EM_SPARC", EM_SPARC, "SPARC"},
  { "EM_386", EM_386, "Intel 80386"},
  { "EM_68K", EM_68K, "Motorola 68000"},
  { "EM_88K", EM_88K, "Motorola 88000"},
  { "EM_860", EM_860, "Intel 80860"},
  { "EM_MIPS", EM_MIPS, "MIPS RS3000"}
};

#define N_SHTYPES 12

elf_attr elf_shtypes[N_SHTYPES] = {
  {"SHT_NULL", SHT_NULL, ""},
  {"SHT_PROGBITS", SHT_PROGBITS, ""},
  {"SHT_SYMTAB", SHT_SYMTAB, ""},
  {"SHT_STRTAB", SHT_STRTAB, ""},
  {"SHT_RELA", SHT_RELA, ""},
  {"SHT_HASH", SHT_HASH, ""},
  {"SHT_DYNAMIC", SHT_DYNAMIC, ""},
  {"SHT_NOTE", SHT_NOTE, ""},
  {"SHT_NOBITS", SHT_NOBITS, ""},
  {"SHT_REL", SHT_REL, ""},
  {"SHT_SHLIB", SHT_SHLIB, ""},
  {"SHT_DYNSYM", SHT_DYNSYM, ""}
};


void print_binary2src(unsigned char* mem, int size) {
  int i;
  printf("\"");
  for (i = 0; i < size; i++) {
    printf("\\x%x", mem[i]);
  }
  printf("\"");
}

void print_elf_header(ElfW(Ehdr)* header) {
  int i, addr_offset = 0;
  printf("Elf32_Ehdr elf_header = {\n");

  /* e_ident[EI_NIDENT] */
  printf("/* %06x */\t\"", addr_offset);
  for (i = 0; i < EI_NIDENT; i++) {
    printf("\\x%x", header->e_ident[i]);
  }
  printf("\",\n");

  addr_offset += sizeof(header->e_ident);

  /* e_type */
  printf("/* %06x */\t%d,\t/* %s */\n", addr_offset, header->e_type, header->e_type < N_OBJTYPES ? object_types[header->e_type].name : "UNKNOWN TYPE");

  addr_offset += sizeof(header->e_type);

  /* e_machine */
  printf("/* %06x */\t%d,\t/* %s */\n", addr_offset, header->e_machine, header->e_machine < N_MACHINES ? elf_machine[header->e_machine].name : "UNKNOWN MACHINE");
}

void test() {
  ElfW(Ehdr) elf_header = {
    "1234567890123456",
    1,
    1,
    1,
    0x803020,
    0x50,
    0x70,
    1,
    30,
    50,
    100,
    1,
    2,
    3
  };

  printf("%d\n", elf_header.e_entry);
}

int main(int argc, char** argv) {
  int fd, n;
  struct stat st;
  unsigned char *mem;
  ElfW(Ehdr)* header;
  if (argc < 2) exit(1);

  fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "failed to open file %s\n", argv[1]);
  }

  if (stat(argv[1], &st) == -1) {
    fprintf(stderr, "failed to stat file %s\n", argv[1]);
    exit(1);
  }

  mem = malloc(sizeof(unsigned int) * st.st_size);

  if ((n = read(fd, mem, st.st_size)) != st.st_size) {
    fprintf(stderr, "failed to read entire file: %d, size = %d\n", n, (int)st.st_size);
    perror(":");
    exit(1);
  }

  header = (ElfW(Ehdr)*) mem;

  print_elf_header(header);
  
  free(mem);
  
  return 0;
}
