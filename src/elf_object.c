/*
  Malelficus - elf_object.c
  --------

  MalELFicus is a malefic tool for dissect and infect ELF binaries.
  Please do not be malefic to use this tool. ;)

  Author: Tiago Natel de Moura <tiago4orion@gmail.com>

  Copyright 2012 by Tiago Natel de Moura. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "defines.h"
#include "util.h"
#include "elf_object.h"
#include "print_table.h"

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


void init_elf_object(elf_object* obj) {
  elf_object obj2;

  obj2.fname = NULL;
  obj2.mem = NULL;
  obj2.elfh = NULL;
  obj2.elfp = NULL;
  obj2.elfs = NULL;

  *obj = obj2;
}

_u8 copy_elf_object(elf_object* out, elf_object *in) {
  assert(in != NULL);
  assert(out != NULL);
  
  out->mem = malloc(sizeof(_u8) * in->st_info.st_size);
  memcpy(out->mem, in->mem, in->st_info.st_size);

  return SUCCESS;
}

#define SET_COLNAME(col, str) strncpy(col.name, str, 80); col.size = 0
#define HTOA(dest, src) snprintf(dest, 80, "0x%x", src)

void pretty_print_elf_header2(ElfW(Ehdr)* header) {
  tb_header h;
  tb_line line;
  /* tb_column e_machine_c1, e_machine_c2, e_machine_c3; */
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

  if (header->e_type == ET_LOPROC || header->e_type == ET_HIPROC || header->e_type >= N_OBJTYPES) {
    SET_COLNAME(cols[2], "Processor specific");
  } else {
    SET_COLNAME(cols[2], object_types[header->e_type].desc);
  }

  line.col = cols;
  line.n_col = 3;

  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_version");
  SET_COLNAME(cols[1], "Version");
  snprintf(tmp_str, 80, "%d", header->e_version);
  SET_COLNAME(cols[2], tmp_str);

  print_table_line(&line, 0, 80);

  SET_COLNAME(cols[0], "e_entry");
  SET_COLNAME(cols[1], "Entry Point");

  HTOA(tmp_str, header->e_entry);
  SET_COLNAME(cols[2], tmp_str);

  print_table_line(&line, 0, 80);
  
  /* SAY("\te_version\tVersion\t\t\t\t%d\n", header->e_version); */
  /* SAY("\te_entry\t\tEntry point:\t\t\t0x%x\n", header->e_entry); */
  /* SAY("\te_phoff\t\tPHT offset\t\t\t0x%x\n", header->e_phoff); */
  /* SAY("\te_shoff\t\tSHT offset\t\t\t0x%x\n", header->e_shoff); */
  /* SAY("\te_ehsize\tELF Header size (bytes)\t\t%d\n", header->e_ehsize); */
  /* SAY("\te_phentsize\tSize of PHT entries\t\t%d\n", header->e_phentsize); */
  /* SAY("\te_phnum\t\tNumber of entries in PHT\t%d\n", header->e_phnum); */
  /* SAY("\te_shentsize\tSize of one entry in SHT\t%d\n", header->e_shentsize); */
  /* SAY("\te_shnum\t\tNumber of sections:\t\t%d\n", header->e_shnum); */
  /* SAY("\te_shstrndx\tSHT index of the section strtab\t%d\n", header->e_shstrndx); */
  
}

void pretty_print_elf_header(ElfW(Ehdr)* header) {

  assert(header != NULL);
  SAY("--------------------------------------------------------------------------------\n");
  SAY("\t\t\t\tELF HEADER\n");
  SAY("--------------------------------------------------------------------------------\n");
  SAY("\tstruct member\tDescription\t\t\tValue\n");
  SAY("\te_type\t\tObject type\t\t\t");
  if (header->e_type == ET_LOPROC || header->e_type == ET_HIPROC) {
    SAY("Processor-specific\n");
  } else {
    if (header->e_type < N_OBJTYPES) {
      SAY("%s\n", object_types[header->e_type].desc);
    }
  }

  SAY("\te_machine\tMachine\t\t\t\t");
  if (header->e_machine >= 8) {
    SAY("Unknown machine\n");
  } else {
    SAY("%s\n", elf_machine[header->e_machine].desc);
  }

  SAY("\te_version\tVersion\t\t\t\t%d\n", header->e_version);
  SAY("\te_entry\t\tEntry point:\t\t\t0x%x\n", header->e_entry);
  SAY("\te_phoff\t\tPHT offset\t\t\t0x%x\n", header->e_phoff);
  SAY("\te_shoff\t\tSHT offset\t\t\t0x%x\n", header->e_shoff);
  SAY("\te_ehsize\tELF Header size (bytes)\t\t%d\n", header->e_ehsize);
  SAY("\te_phentsize\tSize of PHT entries\t\t%d\n", header->e_phentsize);
  SAY("\te_phnum\t\tNumber of entries in PHT\t%d\n", header->e_phnum);
  SAY("\te_shentsize\tSize of one entry in SHT\t%d\n", header->e_shentsize);
  SAY("\te_shnum\t\tNumber of sections:\t\t%d\n", header->e_shnum);
  SAY("\te_shstrndx\tSHT index of the section strtab\t%d\n", header->e_shstrndx);

  SAY("-------------------------------------------------------------------------------\n");
}

void pretty_print_pht(ElfW(Ehdr)* header, ElfW(Phdr)* pheaders) {
  int i;
  assert(pheaders != NULL);
  
  SAY("-------------------------\n");
  SAY("|  Program Header Table |\n");
  SAY("-------------------------\n");
  SAY("| N |      Offset\t|\n");
  SAY("-------------------------\n");
  
  for (i = 0; i < header->e_phnum; ++i) {
    ElfW(Phdr)* h = (ElfW(Phdr)*)(pheaders + i);
    printf("| %d |\t0x%08x\t|\n", i, h->p_offset);
  }

  SAY("-------------------------\n");
}

void pretty_print_sht(elf_object* elf, ElfW(Ehdr)* header, ElfW(Shdr)* sections) {
  int i;

  assert(header != NULL);
  assert(sections != NULL);
  SAY("--------------------------------------------------------------------------------\n");
  SAY("|\t\t\t\tSection Header Table\t\t\t\t|\n");
  SAY("--------------------------------------------------------------------------------\n");
  SAY("| N |\tAddr\t\t|\tOffset\t|\tName\t\t|    Type\t|\n");
  SAY("--------------------------------------------------------------------------------\n");
  for (i = 0; i < header->e_shnum; ++i) {
    ElfW(Shdr) *sect = (ElfW(Shdr)*)(sections + i);
    char sect_name[12];
    strncpy(sect_name, (char*) elf->mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name, 12);
    
    _u8 sht_type = sect->sh_type;
    SAY("| %d |\t0x%08x\t|\t0x%04x\t| %s%s|  %s\t|\n", i, sect->sh_addr, sect->sh_offset, sect_name, strlen(sect_name) > 5 ? "\t\t" : "\t\t\t", sht_type >= N_SHTYPES-1 ? "UNKNOWN" : elf_shtypes[sht_type].name);
  }
}

/**
 * Algorithm based on Elfrw function elfr_symtable_dump at (https://github.com/felipensp/ELFrw)
 *
 * TODO: *rewrite this*
 */
void pretty_print_strtab(elf_object* elf, ElfW(Ehdr)* header, ElfW(Shdr)* sections) {
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
