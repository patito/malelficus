/*
  Malelficus
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
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h> /* ElfW(type) and others */

#include "defines.h"
#include "types.h"
#include "elf_object.h"

/**
 * Macros
 */
#define LOG_RAW(out, format...) fprintf(out, format)
#define SAY(format...) LOG_RAW(stdout, format)
#define LOG(format...) LOG_RAW(stdout, "[!] " format)
#define LOG_SUCCESS(format...) LOG_RAW(stdout, "[+] " format)
#define LOG_ERROR(format...) LOG_RAW(stderr, "[-] ERROR: " format); exit(ERROR)
#define LOG_WARN(format...) LOG_RAW(stderr, "[-] WARNING: " format)
#define LOG_OFFSET(desc_format, value) \
  if (quiet_mode) { \
    LOG_RAW(stdout, "0x%x", value); \
  } else LOG_RAW(stdout, desc_format, value)

/**
 * function prototypes
 */
void help(), help_entry_point(), help_dissect();
void read_file(elf_object*);
_u8 check_elf();
_u8 saveFile(const char*, _u8*, off_t);
_u8 entry_point(int argc, char** argv);
_u8 dissect(int argc, char** argv);
_u8 pht(int argc, char** argv);

/**
 * Global variables
 */
int quiet_mode = 0, verbose_mode = 0;

/**
 * Object file types
 * see ELF Format Specification for more details
 */
object_ftype object_types[5] = {
  {"ET_NONE", ET_NONE, "No file type"},
  {"ET_REL", ET_REL, "Relocatable file"},
  {"ET_EXEC", ET_EXEC, "Executable file"},
  {"ET_DYN", ET_DYN, "Shared Object file"},
  {"ET_CORE", ET_CORE, "Core file"}
};

/**
 * Software design
 *
 * The main goal of malELFicus is help in the process of virus development,
 * for this purpose we need split the software in tasks. Each task have
 * your own options and parameters so that I've decided to propagate the
 * arguments of user to functions callback that handle each task.
 */

/**
 * Handle entry point
 *
 * ./malelficus entry_point [-qhvg] [-u address] [-i <input-file>] [-o <output-file>]
 *
 * -q quiet mode
 * -h entry point help
 * -v verbose mode
 * -g get binary entry point
 * -u <offset> update entry point offset
 * -i <file> input binary file
 * -o <file> output binary file
 */
_u8 entry_point(int argc, char** argv) {
  ElfW(Ehdr) *header = NULL;
  _u8 action = 0;
  _u32 offset_update = 0x00;
  int opt;
  elf_object input, output;

  init_elf_object(&input);
  init_elf_object(&output);

#define ACTION_GET 0x01
#define ACTION_UPDATE 0x02

  while((opt = getopt(argc, argv, "qhvgu:i:o:")) != -1) {
    switch(opt) {
    case 'h':
      help_entry_point();
      break;
    case 'q':
      quiet_mode = 0x01;
      break;
    case 'v':
      verbose_mode = 0x01;
      break;
    case 'g':
      action = ACTION_GET;
      break;
    case 'u':
      action = ACTION_UPDATE;
      sscanf(optarg, "%x", &offset_update);
      break;
    case 'i':
      input.fname = optarg;
      break;
    case 'o':
      output.fname = optarg;
      break;
    case ':':
      LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
      help();
      break;
    case '?':
      LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
      help_entry_point();
    }
  }

  if (input.fname == NULL) {
    LOG_WARN("No ELF binary file set to dissect!\n");
    help_entry_point();
  }

  read_file(&input);
  if (check_elf(input.mem) == ERROR) {
    LOG_ERROR("invalid ELF!!! aborting...\n");
  }

  header = (Elf32_Ehdr*)input.mem;

  if (!header) {
    LOG_ERROR("file not mapped to memory.\n");
  }

  if (action != ACTION_GET && action != ACTION_UPDATE) {
    LOG_ERROR("Command 'entry_point' need the option -g or -u\n");
  }

  if (action == ACTION_GET) {
    LOG_OFFSET("Entry point: 0x%x\n", header->e_entry);
  } else if (action == ACTION_UPDATE) {
    if (output.fname != NULL) {
      copy_elf_object(&output, &input);
      header = (ElfW(Ehdr*)) output.mem;
      header->e_entry = offset_update;
      saveFile(output.fname, output.mem, output.st_info.st_size);
      free(output.mem);
    } else {
      LOG_ERROR("In command 'entry_point' the option -u needs the option -o <file>\n");
    }
  }

  if (input.mem != NULL) {
    munmap(input.mem, input.st_info.st_size);
  }
  
  return SUCCESS;
}

_u8 dissect(int argc, char** argv) {
  ElfW(Ehdr) *header = NULL;
  ElfW(Phdr) *pheaders = NULL;
  ElfW(Shdr) *sections = NULL;
  elf_object input;
  _u32 i;
  int opt;

  input.fname = NULL;

#define ACTION_DISSECT 0x01
#define ACTION_PHT 0x02

  while((opt = getopt(argc, argv, "hvi:")) != -1) {
    switch(opt) {
    case 'h':
      help_dissect();
      break;
    case 'v':
      verbose_mode = 0x01;
      break;
    case 'i':
      input.fname = optarg;
      break;
    case ':':
      LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
      help();
      break;
    case '?':
      LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
      help_dissect();
    }
  }

  if (input.fname == NULL) {
    LOG_WARN("No ELF binary file set to dissect!\n");
    help_dissect();
  }

  read_file(&input);
  if (check_elf(input.mem) == ERROR) {
    LOG_ERROR("invalid ELF!!! aborting...\n");
  }

  header = (ElfW(Ehdr)*)input.mem;

  if (!header) {
    LOG_ERROR("file not mapped to memory.\n");
  }

  pheaders = (ElfW(Phdr)*) (input.mem + header->e_phoff);
  sections = (ElfW(Shdr)*) (input.mem + header->e_shoff);

  SAY(" Object type: \t\t\t");
  if (header->e_type == ET_LOPROC || header->e_type == ET_HIPROC) {
    SAY("Processor-specific");
  } else {
    if (header->e_type < 5) {
      SAY("%s\n", object_types[header->e_type].desc);
    }
  }

  printf("Entry point: 0x%x\n", header->e_entry);
  printf("Number of sections: %hd\n", header->e_shnum);

  SAY("-------------------\n");
  SAY("|     Headers     |\n");
  for (i = 0; i < header->e_phnum; ++i) {
    printf("| Offset: 0x%x\n", ((ElfW(Phdr)*)(pheaders + i))->p_offset);
  }

  printf("SECTIONS: \n");

  for (i = 0; i < header->e_shnum; ++i) {
    printf("[%d] Offset: 0x%x, name = %s\n", i, ((ElfW(Shdr)*)(sections + i))->sh_addr, input.mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name);
  }
  
  return SUCCESS;
}

int main(int argc, char **argv) {
  if(argc == 1) {
    LOG_WARN("This program needs arguments....\n\n");
    help(1);
  }

  if (!strcmp("dissect", argv[1])) {
    dissect(argc, argv);
  } else  
    if (!strcmp("entry_point", argv[1])) {
      entry_point(argc, argv);
    }

  return 0;
}

void read_file(elf_object* elf) {
  elf->fd = open(elf->fname, O_RDWR);

  if (elf->fd == -1) {
    LOG_ERROR("Erro ao abrir arquivo!\n");
    exit(1);
  }

  fstat(elf->fd, &elf->st_info);

  elf->mem = mmap(0, elf->st_info.st_size, PROT_READ, MAP_SHARED, elf->fd, 0);
	
  if (elf->mem == MAP_FAILED) {
    LOG_ERROR("mmap falhou!\n");
    exit(1);
  }
}

_u8 saveFile(const char* fname, _u8 *mem, off_t size) {
  int h_fd;

  h_fd = open(fname, O_RDWR|O_FSYNC|O_CREAT, S_IRWXU);

  if (h_fd == -1) {
    LOG_ERROR("Failed to open file to write: %s\n", fname);
  }

  if (write(h_fd, mem, size) != size) {
    LOG_ERROR("Failed to write the entire file...\n");
  }

  return SUCCESS;
}


_u8 check_elf(_u8* mem) {
  ElfW(Ehdr) *header;
  _u8 valid = SUCCESS;

  header = (ElfW(Ehdr)*)mem;

  if (!header) {
    LOG_ERROR("file not mapped to memory.\n");
  }

  if (memcmp(header->e_ident, ELFMAG, SELFMAG) == 0) {
    valid = SUCCESS;
  } else {
    valid = ERROR;
  }
  
  return valid;
}

void help() {
  const  _u8* banner = (_u8*)
#include "malelficus_banner.h"
    ;

  SAY("%s\n", banner);
  SAY("PRESS ENTER TO CONTINUE\n");
  getc(stdin);
  printf("./malelficus <command> <options>\n\n");

  SAY(" Commands:\n");
  SAY(" \tview\n");
  SAY(" \tentry_point\n");
  
  SAY("\n");
  SAY("Use:\n \t./malelficus command -h\n to get help about the command.\n"); 

  printf(" -h\tprint this help and exit\n");

  exit(SUCCESS);
}


void help_entry_point() {
  SAY("Entry point command\n");
  SAY("./malelficus entry_point [-qhvg] [-u address] [-i <input-file>] [-o <output-file>]\n");
  SAY(" -q\tquiet mode\n");
  SAY(" -h\tentry point help\n");
  SAY(" -v\tverbose mode\n");
  SAY(" -g\tget binary entry point\n");
  SAY(" -u <offset>\tupdate entry point\n");
  SAY(" -i <file>\tinput binary file\n");
  SAY(" -o <file>\toutput binary file\n");

  exit(SUCCESS);
}

void help_dissect() {
  SAY("Dissect command\n");
  SAY("./malelficus dissect [-hv] -i <input file>\n");
  SAY(" -h\tdissect help\n");
  SAY(" -v\t verbose mode\n");
  SAY(" -i <file>\t Input binary file\n");
  exit(SUCCESS);
}

