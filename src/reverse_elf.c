#include <stdio.h>
#include "reverse_elf.h"
#include "elf_object.h"
#include "types.h"
/*
 
  Extracted from elf.h
#define EI_NIDENT (16)

typedef struct
{
  unsigned char	e_ident[EI_NIDENT];	// Magic number and other info 
  Elf32_Half	e_type;			// Object file type 
  Elf32_Half	e_machine;		// Architecture 
  Elf32_Word	e_version;		// Object file version 
  Elf32_Addr	e_entry;		// Entry point virtual address 
  Elf32_Off	e_phoff;		// Program header table file offset 
  Elf32_Off	e_shoff;		// Section header table file offset 
  Elf32_Word	e_flags;		// Processor-specific flags 
  Elf32_Half	e_ehsize;		// ELF header size in bytes 
  Elf32_Half	e_phentsize;		// Program header table entry size 
  Elf32_Half	e_phnum;		// Program header table entry count 
  Elf32_Half	e_shentsize;		// Section header table entry size 
  Elf32_Half	e_shnum;		// Section header table entry count 
  Elf32_Half	e_shstrndx;		// Section header string table index 
} Elf32_Ehdr;

// Program segment header.  

typedef struct
{
  Elf32_Word	p_type;			// Segment type 
  Elf32_Off	p_offset;		// Segment file offset 
  Elf32_Addr	p_vaddr;		// Segment virtual address 
  Elf32_Addr	p_paddr;		// Segment physical address 
  Elf32_Word	p_filesz;		// Segment size in file 
  Elf32_Word	p_memsz;		// Segment size in memory 
  Elf32_Word	p_flags;		// Segment flags 
  Elf32_Word	p_align;		// Segment alignment 
} Elf32_Phdr;

typedef struct
{
  Elf32_Word	sh_name;		// Section name (string tbl index) 
  Elf32_Word	sh_type;		// Section type 
  Elf32_Word	sh_flags;		// Section flags 
  Elf32_Addr	sh_addr;		// Section virtual addr at execution 
  Elf32_Off	sh_offset;		// Section file offset 
  Elf32_Word	sh_size;		// Section size in bytes 
  Elf32_Word	sh_link;		// Link to another section 
  Elf32_Word	sh_info;		// Additional section information 
  Elf32_Word	sh_addralign;		// Section alignment 
  Elf32_Word	sh_entsize;		// Entry size if section holds table 
} Elf32_Shdr;


*/

#define TOP_TEMPLATE "#include <elf.h>\n\n"
#define PRINT_C(format...) fprintf(fd, format)
#define PRINT_FILEADDR PRINT_C("/* %06x */", file_addr);
#define PRINT_CHAR(str, size, desc) do { PRINT_FILEADDR \
 PRINT_C("\t\"");                                         \
 for (_i_ = 0; _i_ < size; ++_i_) { \
   PRINT_C("\\x%x", str[_i_]); } \
 PRINT_C("\",\n"); file_addr += size; } while(0)

#define PRINT_WORD(value, desc) do { PRINT_FILEADDR PRINT_C("\t%d,\t/* %s */\n", value, desc); file_addr += sizeof(value); } while(0)
#define PRINT_WORD_END(value, desc) do { PRINT_FILEADDR PRINT_C("\t%d\t/* %s */\n", value, desc); file_addr += sizeof(value); } while(0)
#define PRINT_HALF(value, desc) PRINT_WORD(value, desc)
#define PRINT_ADDR(value, desc) do { PRINT_FILEADDR PRINT_C("\t0x%x,\t/* %s */\n", value, desc); file_addr += sizeof(value); } while(0)
#define PRINT_ADDR_END(value, desc) do { PRINT_FILEADDR PRINT_C("\t0x%x\t/* %s */\n", value, desc); file_addr += sizeof(value); } while(0)
#define PRINT_OFF(value, desc) PRINT_ADDR(value, desc)
#define PADCHAR 0


_u8 reverse_elf2c(elf_object* elf, FILE* fd) {
  ElfW(Ehdr)* header;
  ElfW(Phdr)* pheader;
  ElfW(Shdr)* sections;
  unsigned int file_addr = 0, _i_, i, j, l;

  header = (ElfW(Ehdr)*) elf->mem;
  pheader = (ElfW(Phdr)*) (elf->mem + header->e_phoff);
  sections = (ElfW(Shdr)*) (elf->mem + header->e_shoff);

  PRINT_C(TOP_TEMPLATE);

  PRINT_C("Elf32_Ehdr elf_header = {\n");
  PRINT_CHAR(header->e_ident, EI_NIDENT, "Magic numbers");
  PRINT_HALF(header->e_type, GET_ATTR_DESC(get_header_type(header->e_type)));
  PRINT_HALF(header->e_machine, GET_ATTR_NAME(get_machine(header->e_machine)));
  PRINT_WORD(header->e_version, "CURRENT VERSION");
  PRINT_ADDR(header->e_entry, "Entry point");
  PRINT_OFF(header->e_phoff, "Program Header Table file offset");
  PRINT_OFF(header->e_shoff, "Section Header Table file offset");
  PRINT_WORD(header->e_flags, "Processor Spacefic-Flags");
  PRINT_HALF(header->e_ehsize, "ELF Header size in bytes");
  PRINT_HALF(header->e_phentsize, "Program Header Table entry size");
  PRINT_HALF(header->e_phnum, "Program Header Table entry count");
  PRINT_HALF(header->e_shentsize, "Section Header Table entry size");
  PRINT_HALF(header->e_shnum, "Section Header Table entry size");
  PRINT_WORD_END(header->e_shstrndx, "Section Header string table index");
  PRINT_C("};\n\n");
  
  PRINT_C("Elf32_Phdr pht = {\n");
  for (i = 0; i < header->e_phnum; i++) {
    PRINT_C("{\n");
    ElfW(Phdr)* p = (ElfW(Phdr)*) (pheader + i);
    PRINT_OFF(p->p_type, GET_ATTR_NAME(get_segment_type(p->p_type)));
    PRINT_OFF(p->p_offset, "Segment file offset ");
    PRINT_ADDR(p->p_vaddr, "Segment virtual address");
    PRINT_ADDR(p->p_paddr, "Segment physical address ");
    PRINT_WORD(p->p_filesz, "Segment size in file");
    PRINT_WORD(p->p_memsz, "Segment size in memory");
    PRINT_WORD(p->p_flags, "Segment flags");
    PRINT_WORD(p->p_align, "Segment alignment");
    PRINT_C("}");
    if (i < (unsigned)(header->e_phnum - 1)) {
      PRINT_C(",");
    }
    
    PRINT_C("\n");
  }

  PRINT_C("\n");

  /* Dumping sections */

  PRINT_C("const unsigned char* segments = \n");

  for (i = 0; i < header->e_shnum; i++) {
    ElfW(Shdr)* s = (ElfW(Shdr)*) (sections + i);
    unsigned char* buf = (unsigned char*) (elf->mem + s->sh_offset);
    _u8 count_str = 0;
    /* Jump SHT_NULL */
    if (s->sh_type == 0x00) {
      continue;
    }

    file_addr = s->sh_offset;

    PRINT_C("/* Dump of section: %s */\n", (char*) elf->mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name);
    for (j = 0; j < s->sh_size; j+=2) {
      if (count_str == 0) {
        PRINT_C("/* %x */\t\"", file_addr);
      }

      if ((j+1) < s->sh_size) {
        PRINT_C("\\x%02x", *(buf+1));
        file_addr += sizeof(*(buf+1));
      }

      PRINT_C("\\x%02x", *buf);
      file_addr += sizeof(*buf);
      
      if (j < (s->sh_size) && count_str >= 14) {
        PRINT_C("\"\n");
        count_str = 0;
      } else {
        count_str+=2;
      }

      buf = buf + 2;
    }

    PRINT_C("\n");
  }

  PRINT_C("Elf32_Shdr sht = {\n");
  for (i = 0; i < header->e_shnum; i++) {
    ElfW(Shdr)* s = (ElfW(Shdr)*) (sections + i);
    PRINT_C("{\n");
    PRINT_C("/* Section: %s */\n", (char*) elf->mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name);
            
    PRINT_WORD(s->sh_name, "Section name (string tbl index)");
    PRINT_OFF(s->sh_type, GET_ATTR_NAME(get_section_type(s->sh_type)));
    PRINT_OFF(s->sh_flags, "Section flags");
    PRINT_ADDR(s->sh_addr, "Section virtual addr at execution");
    PRINT_OFF(s->sh_offset, "Section file offset");
    PRINT_WORD(s->sh_size, "Section size in bytes");
    PRINT_WORD(s->sh_link, "Link to another section");
    PRINT_WORD(s->sh_info, "Additional section information");
    PRINT_WORD(s->sh_addralign, "Section alignment ");
    PRINT_WORD(s->sh_entsize, "Entry size if section holds table");
    PRINT_C("}");
    if (i == (unsigned)(header->e_shnum - 1)) {
      PRINT_C(",");
    }
    PRINT_C("\n");
  }

  printf("header pointer: %p\n", header);
  printf("pht pointer: %p\n", pheader);
  printf("sht pointer: %p\n", sections);
  return 0; 
}
