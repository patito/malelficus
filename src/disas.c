#include "disas.h"
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

#include <BeaEngine.h>

#define _P(x...) fprintf(outfd, x)
#define _PDIRECTIVE(x...) _P(x)
#define _PISN(x...) _P("\t" x)
#define _PLABEL(x...) _P(x);

void malelf_disas_ehdr(ElfW(Ehdr)* ehdr, FILE* outfd) {
    _PDIRECTIVE("BITS 32\n");
    _PISN("%%assign origin 0x08048000\n\n");
    _P("ehdr:\t\t\t\t\t; Elf32_Ehdr\n");
    _PISN("db\t0x%02x, \"%c%c%c\", %d, %d, %d, %d\t\t; e_ident\n",
          ehdr->e_ident[0],
          ehdr->e_ident[1],
          ehdr->e_ident[2],
          ehdr->e_ident[3],
          ehdr->e_ident[4],
          ehdr->e_ident[5],
          ehdr->e_ident[6],
          ehdr->e_ident[7]);
    _PISN("times 8\tdb      0\n");
    _PISN("dw\t%d\t\t\t; e_type\n", ehdr->e_type);
    _PISN("dw\t%d\t\t\t; e_machine\n", ehdr->e_machine);
    _PISN("dd\t%d\t\t\t; e_version\n", ehdr->e_version);
    _PISN("dd\t0x%08x\t\t\t; e_entry\n", ehdr->e_entry);
    _PISN("dd\t0x%x\t\t; e_phoff\n", ehdr->e_phoff);
    _PISN("dd\t0x%x\t\t\t; e_shoff\n", ehdr->e_shoff);
    _PISN("dd\t%d\t\t\t; e_flags\n", ehdr->e_flags);
    _PISN("dw\t0x%x\t\t; e_ehsize\n", ehdr->e_ehsize);
    _PISN("dw\t0x%x\t\t; e_phentsize\n", ehdr->e_phentsize);
    _PISN("dw\t%d\t\t\t; e_phnum\n", ehdr->e_phnum);
    _PISN("dw\t0x%x\t\t\t; e_shentsize\n", ehdr->e_shentsize);
    _PISN("dw\t%d\t\t\t; e_shnum\n", ehdr->e_shnum);
    _PISN("dw\t%d\t\t\t; e_shstrndx\n", ehdr->e_shstrndx);
    _PISN("ehdrsize\tequ\t$ - ehdr\t\t; ehdr size\n");

    /*_start:

      ; your program here
        mov eax, 1
        mov ebx, 42
        int 0x80

      filesize      equ     $ - $$

    */
}

void malelf_disas_phdr(elf_t* elf, FILE* outfd) {
    ElfW(Ehdr)* ehdr = elf->elfh;
    ElfW(Phdr)* phdr = elf->elfp;
    int i;

    for (i = 0; i < ehdr->e_phnum; i++) {
        ElfW(Phdr)* p = (ElfW(Phdr)*) (phdr + i);
        _P("\t; PHT %d\n", i);
        _PLABEL("phdr_%d:\t\t\t\t\t; Elf32_Phdr\n", i);
        _PISN("dd\t0x%x\t\t\t; p_type\n", p->p_type);
        _PISN("dd\t0x%x\t\t\t; p_offset\n", p->p_offset);
        _PISN("dd\t0x%x\t\t\t; p_vaddr\n", p->p_vaddr);
        _PISN("dd\t0x%x\t\t\t; p_paddr\n", p->p_paddr);
        _PISN("dd\t%d\t\t\t; p_filesz\n", p->p_filesz);
        _PISN("dd\t%d\t\t\t; p_memsz\n", p->p_memsz);
        _PISN("dd\t%d\t\t\t; p_flags\n", p->p_flags);
        _PISN("dd\t0x%x\t\t\t; p_align\n", p->p_align);
    }
    _P("\n");
    _PISN("phdrsize\tequ\t$ - phdr_0\n\n");
}

void malelf_disas_sht(malelf_object* obj, FILE* outfd) {
    ElfW(Ehdr)* ehdr = obj->elf.elfh;
//    ElfW(Phdr)* phdr = obj->elf.elfp;
    ElfW(Shdr)* shdr = obj->elf.elfs;
    int i;

    _P("\t; Section Header Table\n");
    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfW(Shdr)* s = (ElfW(Shdr)*) (shdr + i);
        _P("sht_%d:\n", i);
        _PISN("dd\t0x%x\t\t; sh_name Section name (string tbl index)\n", s->sh_name);
        _PISN("dd\t0x%x\t\t; sh_type Section type\n", s->sh_type);
        _PISN("dd\t0x%x\t\t; sh_flags Section flags\n", s->sh_flags);
        _PISN("dd\t0x%08x\t; sh_addr Section virtual addr at execution\n", s->sh_addr);
        _PISN("dd\t0x%x\t\t; sh_offset Section file offset\n", s->sh_offset);
        _PISN("dd\t0x%x\t\t; sh_size Section size in bytes\n", s->sh_size);
        _PISN("dd\t0x%x\t\t; sh_link Link to another section\n", s->sh_link);
        _PISN("dd\t0x%x\t\t; sh_info Additional section information\n", s->sh_info);
        _PISN("dd\t0x%x\t\t; sh_addralign Section alignment\n", s->sh_addralign);
        _PISN("dd\t0x%x\t\t; sh_entsize Entry size if section holds table\n", s->sh_entsize);
        _P("\n\n");
    }

    _P("\n");
}

void malelf_disas_sections(malelf_object* obj, FILE* outfd) {
    ElfW(Ehdr)* ehdr = obj->elf.elfh;
//    ElfW(Phdr)* phdr = obj->elf.elfp;
    ElfW(Shdr)* shdr = obj->elf.elfs;
    int i;

    _P("\t; Program\n");
    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfW(Shdr)* s = (ElfW(Shdr)*) (shdr + i);
        _u8* mem = obj->mem + s->sh_offset;
        DISASM MyDisasm;
        int len, j = 0, size = 0;
        int Error = 0;

        /* skip SHT_NULL */
        if (s->sh_type != 1)
            continue;

        if ((s->sh_flags & SHF_ALLOC)!=SHF_ALLOC || (s->sh_flags & SHF_EXECINSTR)!= SHF_EXECINSTR)
            continue;

        _P("\t; Disassembly of section %d\n", i);

        _PLABEL(".section_%d:\n", i);
        _PLABEL("%s:\t; 0x%08x\n", GET_SECTION_NAME(obj, ehdr, shdr, i), 0x08048000+s->sh_offset);

        /* ============================= Init the Disasm structure (important !)*/
        (void) memset (&MyDisasm, 0, sizeof(DISASM));

        /* ============================= Init EIP */
        MyDisasm.EIP = (UIntPtr) mem;

        MyDisasm.Options = Tabulation + NasmSyntax + PrefixedNumeral + ShowSegmentRegs;


        /* ============================= Loop for Disasm */
        while ((unsigned)size < s->sh_size && !Error){
            len = Disasm(&MyDisasm);

            if (len != UNKNOWN_OPCODE) {
                size += len;
                _P("%s\n", MyDisasm.CompleteInstr);
                MyDisasm.EIP = MyDisasm.EIP + (UIntPtr)len;
                j++;
            }
            else {
                printf("ERROR\n");
                Error = 1;
            }
        };


        _P("\n\n");
    }

    _P("\n");
}

void malelf_disas(malelf_object* input, FILE* outfd) {
    malelf_disas_ehdr(input->elf.elfh, outfd);
    malelf_disas_phdr(&input->elf, outfd);
    malelf_disas_sections(input, outfd);
    malelf_disas_sht(input, outfd);
}
