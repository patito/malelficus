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
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "defines.h"
#include "util.h"
#include "error.h"
#include "malelf_object.h"
#include "print_table.h"

/**
 * Object file types
 * see ELF Format Specification for more details
 */
elf_attr malelf_object_types[] = {
#include "header_types.inc"
};

/**
 * Possible target machines
 */
elf_attr elf_machine[] = {
#include "machines.inc"
};

/**
 * Possible section types
 */
elf_attr elf_section_types[] = {
#include "section_types.inc"
};

/**
 * Possible segment types
 */
elf_attr elf_segment_types[] = {
#include "segment_types.inc"
};

/**
 * Possible segment flags
 */
elf_attr elf_segment_flags[] = {
#include "segment_flags.inc"
};

void malelf_init_object(malelf_object* obj) {
  obj->fname = NULL;
  obj->is_readonly = 0;
  obj->mem = NULL;
  obj->elf.elfh = NULL;
  obj->elf.elfp = NULL;
  obj->elf.elfs = NULL;
}

_u8 check_elf(malelf_object* obj) {
  assert(obj != NULL);
  assert(obj->fname != NULL);
  assert(obj->elf.elfh != NULL);
 
  _u8 valid = SUCCESS;

  if (memcmp(obj->elf.elfh->e_ident, ELFMAG, SELFMAG) == 0) {
    valid = SUCCESS;
  } else {
    valid = ERROR;
  }
  
  return valid;
}

_i32 malelf_open(malelf_object* obj, char* filename, int flags) {
  assert(obj != NULL);
  assert(filename != NULL);
  _u8 is_creat = (flags & O_CREAT) == O_CREAT;
  
  malelf_init_object(obj);
  obj->fname = filename;
  if (!is_creat) {
    obj->fd = open(filename, flags);
  } else {
    obj->fd = open(filename, flags, 0666);
  }

  if (obj->fd == -1) {
    return errno;
  }

  if (fstat(obj->fd, &obj->st_info) == -1) {
    return errno;
  }

  /**
   * If the file was created right now, then there is no buffer to map in memory.
   */
  if (!is_creat) {
    obj->mem = mmap(0, obj->st_info.st_size, PROT_READ, MAP_SHARED, obj->fd, 0);
    if (obj->mem == MAP_FAILED) {
      return errno;
    }

    MALELF_MAP_ELF(obj);
  }

  return SUCCESS;
}

_i32 malelf_openr(malelf_object* obj, char* filename) {
  return malelf_open(obj, filename, O_RDONLY);
}

_i32 malelf_openw(malelf_object* obj, char* filename) {
  return malelf_open(obj, filename, O_RDWR | O_CREAT | O_TRUNC);
}

void malelf_close(malelf_object* obj) {
  assert(obj != NULL);
  assert(obj->fd != -1);
  if (obj->mem != MAP_FAILED) {
    munmap(obj->mem, obj->st_info.st_size);
  }
}

_u8 malelf_add_section(malelf_object* input, malelf_object* output, malelf_add_section_t options) {
  int i;
  assert(options.name != NULL);
  assert(options.data_fname != NULL);
  LOG_SUCCESS("section name: %s\n", options.name);
  LOG_SUCCESS("section data file: %s\n", options.data_fname);
  LOG_SUCCESS("binary output: %s\n", output->fname);
  LOG_SUCCESS("PHT address: 0x%08x\n", input->elf.elfh->e_phoff);
  LOG_SUCCESS("Section header address: 0x%08x\n", input->elf.elfh->e_shoff);

  if (write(output->fd, input->elf.elfh,  input->elf.elfh->e_ehsize) < input->elf.elfh->e_ehsize) {
    LOG_ERROR("Failed to write() the elf header\n");
    exit(1);
  }

  if (write(output->fd, input->elf.elfp, input->elf.elfh->e_phentsize * input->elf.elfh->e_phnum) < input->elf.elfh->e_phentsize * input->elf.elfh->e_phnum) {
    LOG_ERROR("Failed to write() the elf pht\n");
    exit(1);
  }

  for (i = 0; i < input->elf.elfh->e_shnum; i++) {
    ElfW(Shdr)* s = (ElfW(Shdr)*) (input->elf.elfs + i);
    if (s->sh_addr == 0)
      continue;
    _u8* data = input->mem + s->sh_offset;
    _u8 size = s->sh_size;
    if (write(output->fd, data, size) < size) {
      LOG_ERROR("Failed to write() the sections...\n");
      exit(1);
    }
  }

  if (write(output->fd, input->elf.elfs, input->elf.elfh->e_shnum * input->elf.elfh->e_shentsize) < input->elf.elfh->e_shnum * input->elf.elfh->e_shentsize) {
    LOG_ERROR("Failed to write() the elf sht\n");
    exit(1);
  }


  return 1;
}

elf_attr* get_header_type(ElfW(Half) etype) {
  _u8 i;

  for (i = 0; i < sizeof(malelf_object_types)/sizeof(elf_attr); i++) {
    if (malelf_object_types[i].val == etype) {
      return &malelf_object_types[i];
    }
  }

  return NULL;
}

elf_attr* get_section_type(ElfW(Half) stype) {
  _u8 i;

  for (i = 0; i < sizeof(elf_section_types)/sizeof(elf_attr); i++) {
    if (elf_section_types[i].val == stype) {
      return  &elf_section_types[i];
    }
  }

  return NULL;
}

elf_attr* get_machine(ElfW(Half) emach) {
  _u8 i;

  for (i = 0; i < sizeof(elf_machine)/sizeof(elf_attr); i++) {
    if (elf_machine[i].val == emach) {
      return &elf_machine[i];
    }
  }

  return NULL;
}

elf_attr* get_segment_type(ElfW(Word) segtype) {
  _u32 i;

  for (i = 0; i < sizeof(elf_segment_types)/sizeof(elf_attr); i++) {
    if (elf_segment_types[i].val == segtype) {
      return &elf_segment_types[i];
    }
  }

  return NULL;
}

_u8 copy_malelf_object_raw(malelf_object* out, malelf_object *in) {
  assert(in != NULL);
  assert(out != NULL);

  if (out->is_readonly != 0) {
    LOG_ERROR("output file '%s' is read-only!\n", out->fname);
    exit(1);
  }
  
  out->mem = malloc(sizeof(_u8) * in->st_info.st_size);
  memcpy(out->mem, in->mem, in->st_info.st_size);
  
  return SUCCESS;
}

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
  snprintf(tmp_str, 80, "%d", header->e_version);
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
  snprintf(tmp_str, 80, "%d", header->e_ehsize);
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
  
  for (i = 0; i < header->e_phnum; ++i) {
    ElfW(Shdr) *sect = (ElfW(Shdr)*)(sections + i);
    ITOA(tmp_str, i);
    SET_COLNAME(tb_cols[0], tmp_str);

    HTOA(tmp_str, sect->sh_addr);
    
    SET_COLNAME(tb_cols[1], tmp_str);

    ITOA(tmp_str, sect->sh_offset);
    SET_COLNAME(tb_cols[2], tmp_str);
    
    char sect_name[12];
    strncpy(sect_name, (char*) elf->mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name, 12);
    SET_COLNAME(tb_cols[3], sect_name);
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
