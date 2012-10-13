#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <link.h>

#include <malelf/object.h>
#include <malelf/util.h>
#include <malelf/dissect.h>
#include <malelf/print_table.h>

void pretty_print_elf_header(ElfW(Ehdr)* header) {
  tb_header h;
  tb_line line;
  tb_column cols[3];
  char tmp_str[80];
  
  assert(header != NULL);
  bzero(tmp_str, 80);

  SET_COLNAME(cols[0], "Structure Member");
  SET_COLNAME(cols[1], "Description");
  SET_COLNAME(cols[2], "Value");

  h.col = cols;
  h.n_col = 3;
  
  print_table_header(&h, 0, 80);

  SET_COLNAME(cols[0], "e_type");
  SET_COLNAME(cols[1], "Object Type");

  SET_COLNAME(cols[2], GET_ATTR_DESC(get_header_type(header->e_type)));
  line.col = cols;
  line.n_col = 3;

  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_version");
  SET_COLNAME(cols[1], "Version");
  sprintf(tmp_str, "%d", header->e_version);
  SET_COLNAME(cols[2], tmp_str);

  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_entry");
  SET_COLNAME(cols[1], "Entry Point");

  HTOA(tmp_str, header->e_entry);
  SET_COLNAME(cols[2], tmp_str);

  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_phoff");
  SET_COLNAME(cols[1], "PHT Offset");
  HTOA(tmp_str, header->e_phoff);
  SET_COLNAME(cols[2], tmp_str);

  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_shoff");
  SET_COLNAME(cols[1], "SHT Offset");
  HTOA(tmp_str, header->e_shoff);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_ehsize");
  SET_COLNAME(cols[1], "ELF Header size");
  sprintf(tmp_str, "%d", header->e_ehsize);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_phentsize");
  SET_COLNAME(cols[1], "Size of PHT entries");
  ITOA(tmp_str, header->e_phentsize);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_phnum");
  SET_COLNAME(cols[1], "Number of entries in PHT");
  ITOA(tmp_str, header->e_phnum);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_shentsize");
  SET_COLNAME(cols[1], "Size of one entry in SHT");
  ITOA(tmp_str, header->e_shentsize);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_shnum");
  SET_COLNAME(cols[1], "Number of sections");
  ITOA(tmp_str, header->e_shnum);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_shstrndx");
  SET_COLNAME(cols[1], "SHT symbol index");
  ITOA(tmp_str, header->e_shstrndx);
  SET_COLNAME(cols[2], tmp_str);
  print_table_line(&line, 0, 80);
  
  print_table_header_art(80, 0);
}

void pretty_print_pht(ElfW(Ehdr)* header, ElfW(Phdr)* pheaders) {
  int i;
  tb_header tb_main_header, tb_header;
  tb_line line;
  tb_column tb_main_col[1], tb_cols[2];
  char tmp_str[80];

  assert(header != NULL);
  assert(pheaders != NULL);

  bzero(tmp_str, sizeof(tmp_str));

  SET_COLNAME(tb_main_col[0], "Program Header Table (PHT)");
  tb_main_header.n_col = 1;
  tb_main_header.col = tb_main_col;
  print_table_header(&tb_main_header, 50, 80);

  SET_COLNAME(tb_cols[0], "N");
  SET_COLNAME(tb_cols[1], "Offset");
  tb_header.n_col = 2;
  tb_header.col = tb_cols;
  print_table_header(&tb_header, 50, 80);

  line.n_col = 2;
  line.col = tb_cols;
  
  for (i = 0; i < header->e_phnum; ++i) {
    ElfW(Phdr)* h = (ElfW(Phdr)*)(pheaders + i);
    ITOA(tmp_str, i);
    SET_COLNAME(tb_cols[0], tmp_str);
    HTOA(tmp_str, h->p_offset);
    SET_COLNAME(tb_cols[1], tmp_str);
    print_table_line(&line, 50, 80);
  }

  print_table_header_art(50, 15);
  
}

void pretty_print_sht(malelf_object* elf, ElfW(Ehdr)* header, ElfW(Shdr)* sections) {
  int i;
  tb_header tb_main_header, tb_header;
  tb_line line;
  tb_column tb_main_col[1], tb_cols[5];
  char tmp_str[80];
  char sect_name[12];

  assert(header != NULL);
  assert(sections != NULL);

  bzero(tmp_str, sizeof(tmp_str));

  SET_COLNAME(tb_main_col[0], "Section Header Table (SHT)");
  tb_main_header.n_col = 1;
  tb_main_header.col = tb_main_col;
  print_table_header(&tb_main_header, 80, 80);

  SET_COLNAME(tb_cols[0], "N");
  SET_COLNAME(tb_cols[1], "Addr");
  SET_COLNAME(tb_cols[2], "Offset");
  SET_COLNAME(tb_cols[3], "Name");
  SET_COLNAME(tb_cols[4], "Type");
  tb_header.n_col = 5;
  tb_header.col = tb_cols;
  print_table_header(&tb_header, 80, 80);

  line.n_col = 5;
  line.col = tb_cols;
  
  for (i = 0; i < header->e_shnum; ++i) {
    ElfW(Shdr) *sect = (ElfW(Shdr)*)(sections + i);
    ITOA(tmp_str, i);
    SET_COLNAME(tb_cols[0], tmp_str);

    HTOA(tmp_str, sect->sh_addr);
    
    SET_COLNAME(tb_cols[1], tmp_str);

    ITOA(tmp_str, sect->sh_offset);
    SET_COLNAME(tb_cols[2], tmp_str);

    if (sect->sh_type != SHT_NULL && header->e_shstrndx != 0x00) {
      strncpy(sect_name, (char*) elf->mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name, 12);
      SET_COLNAME(tb_cols[3], sect_name);
    } else {
      SET_COLNAME(tb_cols[3], "");
    }

    SET_COLNAME(tb_cols[4], GET_ATTR_NAME(get_section_type(sect->sh_type)));
    print_table_line(&line, 80, 80);
  }
  
  print_table_header_art(80, 0);
}

/**
 * Algorithm based on Elfrw function elfr_symtable_dump at (https://github.com/felipensp/ELFrw)
 *
 * TODO: *rewrite this*
 */
void pretty_print_strtab(malelf_object* elf, ElfW(Ehdr)* header, ElfW(Shdr)* sections) {
  _u32 i, j, stable = 0, n_entries;
  ElfW(Sym)* elf_sym;
  char sname[14];
  char* sect_name;

  SAY("--------------------------------------------------------------------------------\n");
  SAY("\t\t\t\tSymbol Table\t\t\t\t\n");
  SAY("--------------------------------------------------------------------------------\n");
  SAY("\tSymbol\t\t\t|\tOffset\t\t|\tSection\n");
  SAY("--------------------------------------------------------------------------------\n");
  /* Search the string table */
  for (i = 0; i < header->e_shnum; ++i) {
    if (sections[i].sh_type == SHT_STRTAB
        && sections[i].sh_flags == 0
        && i != header->e_shstrndx) {
      stable = sections[i].sh_offset;
      break;
    }
  }

  /* Search the symbol table */
  for (i = 0; i < header->e_shnum; ++i) {
    if (sections[i].sh_type != SHT_SYMTAB) {
      continue;
    }
    n_entries = sections[i].sh_size / sections[i].sh_entsize;
		
    elf_sym = (ElfW(Sym)*) (elf->mem + sections[i].sh_offset);
		
    for (j = 0; j < n_entries; ++j) {
      strncpy(sname, elf_sym[j].st_name ? (char*) (elf->mem + stable + elf_sym[j].st_name) : "", 14);
      sname[13] = 0;
      sect_name = (char*) elf->mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name;
      printf("%s%s|\t%08x\t|\t\t%s\n", sname, strlen(sname) < 8 ? "\t\t\t\t" : "\t\t\t", elf_sym[j].st_value, sect_name);
    }
  }

  SAY("--------------------------------------------------------------------------------\n");
}
