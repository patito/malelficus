#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#include <beaengine/BeaEngine.h>

#include <malelf/defines.h>
#include <malelf/error.h>
#include <malelf/disas.h>
#include <malelf/util.h>
#include <malelf/object.h>

extern _u8 malelf_quiet_mode;

#define _P malelf_print
#define _PDIRECTIVE _P
#define _PISN malelf_print_isn
#define _PLABEL _P

int malelf_print_isn(FILE* fd, const char* format, ...) {
  va_list args;
  va_start(args, format);
  return malelf_log(fd, "        ", format, args);
}

_i32 malelf_disas_ehdr(ElfW(Ehdr)* ehdr, FILE* fd) {
    _PDIRECTIVE(fd, "BITS 32\n");
    _PISN(fd, "%%assign origin 0x08048000\n\n");
    _P(fd, "ehdr:\t\t\t\t\t; Elf32_Ehdr\n");
    _PISN(fd, "db\t0x%02x, \"%c%c%c\", %d, %d, %d, %d\t\t; e_ident\n",
          ehdr->e_ident[0],
          ehdr->e_ident[1],
          ehdr->e_ident[2],
          ehdr->e_ident[3],
          ehdr->e_ident[4],
          ehdr->e_ident[5],
          ehdr->e_ident[6],
          ehdr->e_ident[7]);
    _PISN(fd, "times 8\tdb      0\n");
    _PISN(fd, "dw\t%d\t\t\t; e_type\n", ehdr->e_type);
    _PISN(fd, "dw\t%d\t\t\t; e_machine\n", ehdr->e_machine);
    _PISN(fd, "dd\t%d\t\t\t; e_version\n", ehdr->e_version);
    _PISN(fd, "dd\t0x%08x\t\t\t; e_entry\n", ehdr->e_entry);
    _PISN(fd, "dd\t0x%x\t\t; e_phoff\n", ehdr->e_phoff);
    _PISN(fd, "dd\t0x%x\t\t\t; e_shoff\n", ehdr->e_shoff);
    _PISN(fd, "dd\t%d\t\t\t; e_flags\n", ehdr->e_flags);
    _PISN(fd, "dw\t0x%x\t\t; e_ehsize\n", ehdr->e_ehsize);
    _PISN(fd, "dw\t0x%x\t\t; e_phentsize\n", ehdr->e_phentsize);
    _PISN(fd, "dw\t%d\t\t\t; e_phnum\n", ehdr->e_phnum);
    _PISN(fd, "dw\t0x%x\t\t\t; e_shentsize\n", ehdr->e_shentsize);
    _PISN(fd, "dw\t%d\t\t\t; e_shnum\n", ehdr->e_shnum);
    _PISN(fd, "dw\t%d\t\t\t; e_shstrndx\n", ehdr->e_shstrndx);
    _PISN(fd, "ehdrsize\tequ\t$ - ehdr\t\t; ehdr size\n");

    /*_start:

      ; your program here
        mov eax, 1
        mov ebx, 42
        int 0x80

      filesize      equ     $ - $$

    */

    return MALELF_SUCCESS;
}

_i32 malelf_disas_phdr(malelf_elf_t* elf, FILE* fd) {
    ElfW(Ehdr)* ehdr = elf->elfh;
    ElfW(Phdr)* phdr = elf->elfp;
    int i;

    for (i = 0; i < ehdr->e_phnum; i++) {
        ElfW(Phdr)* p = (ElfW(Phdr)*) (phdr + i);
        _P(fd, "\t; PHT %d\n", i);
        _PLABEL(fd, "phdr_%d:\t\t\t\t\t; Elf32_Phdr\n", i);
        _PISN(fd, "dd\t0x%x\t\t\t; p_type\n", p->p_type);
        _PISN(fd, "dd\t0x%x\t\t\t; p_offset\n", p->p_offset);
        _PISN(fd, "dd\t0x%x\t\t\t; p_vaddr\n", p->p_vaddr);
        _PISN(fd, "dd\t0x%x\t\t\t; p_paddr\n", p->p_paddr);
        _PISN(fd, "dd\t%d\t\t\t; p_filesz\n", p->p_filesz);
        _PISN(fd, "dd\t%d\t\t\t; p_memsz\n", p->p_memsz);
        _PISN(fd, "dd\t%d\t\t\t; p_flags\n", p->p_flags);
        _PISN(fd, "dd\t0x%x\t\t\t; p_align\n", p->p_align);
    }
    _P(fd, "\n");
    _PISN(fd, "phdrsize\tequ\t$ - phdr_0\n\n");

    return MALELF_SUCCESS;
}

_i32 malelf_disas_sht(malelf_object* obj, FILE* fd) {
    ElfW(Ehdr)* ehdr = obj->elf.elfh;
    /*    ElfW(Phdr)* phdr = obj->elf.elfp;*/
    ElfW(Shdr)* shdr = obj->elf.elfs;
    int i;

    _P(fd, "\t; Section Header Table\n");
    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfW(Shdr)* s = (ElfW(Shdr)*) (shdr + i);
        _P(fd, "sht_%d:\n", i);
        _PISN(fd, "dd\t0x%x\t\t; sh_name Section name (string tbl index)\n", s->sh_name);
        _PISN(fd, "dd\t0x%x\t\t; sh_type Section type\n", s->sh_type);
        _PISN(fd, "dd\t0x%x\t\t; sh_flags Section flags\n", s->sh_flags);
        _PISN(fd, "dd\t0x%08x\t; sh_addr Section virtual addr at execution\n", s->sh_addr);
        _PISN(fd, "dd\t0x%x\t\t; sh_offset Section file offset\n", s->sh_offset);
        _PISN(fd, "dd\t0x%x\t\t; sh_size Section size in bytes\n", s->sh_size);
        _PISN(fd, "dd\t0x%x\t\t; sh_link Link to another section\n", s->sh_link);
        _PISN(fd, "dd\t0x%x\t\t; sh_info Additional section information\n", s->sh_info);
        _PISN(fd, "dd\t0x%x\t\t; sh_addralign Section alignment\n", s->sh_addralign);
        _PISN(fd, "dd\t0x%x\t\t; sh_entsize Entry size if section holds table\n", s->sh_entsize);
        _P(fd, "\n\n");
    }

    _P(fd, "\n");

    return MALELF_SUCCESS;
}

_i32 malelf_disas_program(malelf_object* obj, FILE* fd) {
    ElfW(Ehdr)* ehdr = obj->elf.elfh;
    /*    ElfW(Phdr)* phdr = obj->elf.elfp;*/
    ElfW(Shdr)* shdr = obj->elf.elfs;
    int i;

    _P(fd, "\t; Program\n");
    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfW(Shdr)* s = (ElfW(Shdr)*) (shdr + i);
        _u8* mem = obj->mem + s->sh_offset;
        DISASM MyDisasm;
        int len, j = 0, size = 0;
        int Error = 0;

        /* skip SHT_NULL */
        if (s->sh_type == SHT_NULL)
            continue;

        /* if ((s->sh_flags & SHF_ALLOC)!=SHF_ALLOC || (s->sh_flags & SHF_EXECINSTR)!= SHF_EXECINSTR) */
        /*     continue; */

        _P(fd, "\t; Disassembly of section %d\n", i);

        _PLABEL(fd, ".section_%d:\n", i);
        if (ehdr->e_shstrndx != 0x00) {
          _PLABEL(fd, "%s:\t; 0x%08x\n", GET_SECTION_NAME(obj, ehdr, shdr, i), 0x08048000+s->sh_offset);
        }

        /*  Init the Disasm structure */
        (void) memset (&MyDisasm, 0, sizeof(DISASM));

        /* Init EIP */
        MyDisasm.EIP = (UIntPtr) mem;

        MyDisasm.Options = Tabulation + NasmSyntax + PrefixedNumeral + ShowSegmentRegs;


        /* Loop for Disasm */
        while ((unsigned)size < s->sh_size && !Error){
            len = Disasm(&MyDisasm);

            if (len != UNKNOWN_OPCODE) {
                size += len;
                _P(fd, "%s\n", MyDisasm.CompleteInstr);
                MyDisasm.EIP = MyDisasm.EIP + (UIntPtr)len;
                j++;
            }
            else {
                LOG_ERROR("ERROR when disassembling offset %d\n", j);
                Error = 1;
            }
        };


        _P(fd, "\n\n");
    }

    _P(fd, "\n");

    return MALELF_SUCCESS;
}

_i32 malelf_disas_flat(malelf_object* obj, FILE* fd) {
  DISASM MyDisasm;
  unsigned size = 0;
  int len;
  int Error = 0;

  _P(fd, "\t; Disassembly of binary %s\n", obj->fname);

  /*  Init the Disasm structure */
  (void) memset (&MyDisasm, 0, sizeof(DISASM));

  /* Init EIP */
  MyDisasm.EIP = (UIntPtr) obj->mem;

  MyDisasm.Options = Tabulation + NasmSyntax + PrefixedNumeral + ShowSegmentRegs;

  /* Loop for Disasm */
  while (size < (unsigned)obj->st_info.st_size && !Error){
    len = Disasm(&MyDisasm);

    if (len != UNKNOWN_OPCODE) {
      size += len;
      _P(fd, "%s\n", MyDisasm.CompleteInstr);
      MyDisasm.EIP = MyDisasm.EIP + (UIntPtr)len;
    }
    else {
      printf("ERROR\n");
      Error = 1;
    }
  }

  _P(fd, "\n\n");

  return Error ? MALELF_EDISAS : MALELF_SUCCESS;
}

_i32 malelf_disas_section(malelf_object* obj, char* section, FILE* fd) {
    ElfW(Ehdr)* ehdr = obj->elf.elfh;
    ElfW(Shdr)* shdr = obj->elf.elfs;
    int i;
    int Error = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfW(Shdr)* s = (ElfW(Shdr)*) (shdr + i);
        char* name = NULL;

        /* skip SHT_NULL */
        if (s->sh_type == SHT_NULL)
            continue;

        if (ehdr->e_shstrndx != 0x00) {
          name = GET_SECTION_NAME(obj, ehdr, shdr, i);
        }

        if (name != NULL && !strcmp(name, section)) {
          _PLABEL(fd, "%s:\t; 0x%08x\n", GET_SECTION_NAME(obj, ehdr, shdr, i), 0x08048000+s->sh_offset);
          _u8* mem = obj->mem + s->sh_offset;
          DISASM MyDisasm;
          int len, j = 0, size = 0;
          int Error = 0;

          /*  Init the Disasm structure */
          (void) memset (&MyDisasm, 0, sizeof(DISASM));

          /* Init EIP */
          MyDisasm.EIP = (UIntPtr) mem;

          MyDisasm.Options = Tabulation + NasmSyntax + PrefixedNumeral + ShowSegmentRegs;


          /* Loop for Disasm */
          while ((unsigned)size < s->sh_size && !Error){
            len = Disasm(&MyDisasm);

            if (len != UNKNOWN_OPCODE) {
              size += len;
              _P(fd, "%s\n", MyDisasm.CompleteInstr);
              MyDisasm.EIP = MyDisasm.EIP + (UIntPtr)len;
              j++;
            }
            else {
              LOG_ERROR("ERROR when disassembling offset %d [%02x%02x]\n", j, mem[j], mem[j+1]);
              /* Error = 1; */
              j++;
              size += 1;
            }
          };

          _P(fd, "\n\n");

        }
    }

    _P(fd, "\n");

      return Error ? MALELF_EDISAS : MALELF_SUCCESS;
}

_i32 malelf_disas(malelf_object* input, FILE* outfd) {
  if (malelf_check_elf(input) == MALELF_SUCCESS) {
    if (malelf_disas_ehdr(input->elf.elfh, outfd) != MALELF_SUCCESS)
      return MALELF_EDISAS;
    
    if (malelf_disas_phdr(&input->elf, outfd) != MALELF_SUCCESS)
      return MALELF_SUCCESS;
    
    if (malelf_disas_program(input, outfd) != MALELF_SUCCESS)
      return MALELF_SUCCESS;

    if (malelf_disas_sht(input, outfd) != MALELF_SUCCESS)
      return MALELF_EDISAS;
    
  } else {
    LOG_WARN("Disassembling as FLAT binary.\n");
    if (malelf_disas_flat(input, outfd) != MALELF_SUCCESS)
      return MALELF_EDISAS;
  }

  return MALELF_SUCCESS;
}
