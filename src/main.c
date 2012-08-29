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
#include "util.h"
#include "error.h"
#include "types.h"
#include "malelf_object.h"
#include "reverse_elf.h"
#include "infect.h"
#include "disas.h"

/**
 * function prototypes
 */
void help(),
help_entry_point(),
help_dissect(),
help_reverse_elf(),
help_infect(),
help_copy(),
help_disas();
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
 * Software design
 *
 * The main goal of malELFicus is help in the process of virus development,
 * for this purpose we need split the software in tasks. Each task have
 * your own options and parameters so that I've decided to propagate the
 * arguments of user to function callback that handle each task.
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
  _u8 action = 0;
  _u32 offset_update = 0x00;
  int opt;
  malelf_object input, output;

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
    LOG_WARN("No ELF binary file set to get entry point!\n");
    help_entry_point();
  }

  malelf_openr(&input, input.fname);
  
  if (check_elf(input.mem) == ERROR) {
    LOG_ERROR("invalid ELF!!! aborting...\n");
  }

  if (action != ACTION_GET && action != ACTION_UPDATE) {
    LOG_ERROR("Command 'entry_point' need the option -g or -u\n");
  }

  if (action == ACTION_GET) {
    LOG_OFFSET("Entry point: 0x%x\n", input.elf.elfh->e_entry);
  } else if (action == ACTION_UPDATE) {
    if (output.fname != NULL) {
      copy_malelf_object_raw(&output, &input);
      output.elf.elfh->e_entry = offset_update;
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

_u8 copy(int argc, char** argv) {
  malelf_object input, output;
  char *input_filename = NULL, *output_filename = NULL;
  int opt, copy_opt = 0;
  malelf_add_section_t add_section;
#define ADD_SECTION 0x01

  input.fname = NULL;
  output.fname = NULL;

  while((opt = getopt(argc, argv, "han:d:i:o:")) != -1) {
    switch(opt) {
    case 'h':
      help_copy();
      break;
    case 'a':
      copy_opt |= ADD_SECTION;
      break;
    case 'n':
      add_section.name = optarg;
      break;
    case 'd':
      add_section.data_fname = optarg;
      break;
    case 'i':
      input_filename = optarg;
      break;
    case 'o':
      output_filename = optarg;
      break;
    case ':':
      LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
      help();
      break;
    case '?':
      LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
      help_copy();
    }
  }

  if (input_filename == NULL) {
    LOG_WARN("No ELF binary file set to copy. Use -i\n");
    help_copy();
  }

  if (output_filename == NULL) {
    LOG_WARN("No ELF binary output file. Use -o\n");
    help_copy();
  }

  int ret = SUCCESS;

  if ((ret = malelf_openr(&input, input_filename)) != SUCCESS) {
    malelf_perror(ret);
  }

  if ((ret = malelf_openw(&output, output_filename)) != SUCCESS) {
    malelf_perror(ret);
  }

  if ((copy_opt & ADD_SECTION) == ADD_SECTION) {
    malelf_add_section(&input, &output, add_section);
  }

  malelf_close(&input);
  malelf_close(&output);
  
  return 0;
}

_u8 dissect(int argc, char** argv) {
  malelf_object input;
  _u16 option = 0;
  char* input_filename = NULL;
  int opt;

#define DISPLAY_EHT 0x01
#define DISPLAY_PHT 0x02
#define DISPLAY_SHT 0x04
#define DISPLAY_STRTAB 0x08

  input.fname = NULL;

#define ACTION_DISSECT 0x01
#define ACTION_PHT 0x02

  while((opt = getopt(argc, argv, "hepsSi:")) != -1) {
    switch(opt) {
    case 'h':
      help_dissect();
      break;
    case 'e':
      option |= DISPLAY_EHT;
      break;
    case 'p':
      option |= DISPLAY_PHT;
      break;
    case 's':
      option |= DISPLAY_SHT;
      break;
    case 'S':
      option |= DISPLAY_STRTAB;
      break;
    case 'i':
      input_filename = optarg;
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

  if (input_filename == NULL) {
    LOG_WARN("No ELF binary file set to dissect!\n");
    help_dissect();
  }

  if (option == 0) {
    option = DISPLAY_EHT | DISPLAY_SHT | DISPLAY_PHT | DISPLAY_STRTAB;
  }

  int error = SUCCESS;

  if ((error = malelf_openr(&input, input_filename)) != SUCCESS) {
    malelf_perror(error);
    malelf_fatal(error);
  }

  elf_t *elf = &input.elf;

  //malelf_dissect(elf, option);

  if ((option & DISPLAY_EHT) == DISPLAY_EHT) {
    pretty_print_elf_header(elf->elfh);
    SAY("\n");
  }

  if ((option & DISPLAY_PHT) == DISPLAY_PHT) {
    pretty_print_pht(elf->elfh, elf->elfp);
    SAY("\n");
  }

  if ((option & DISPLAY_SHT) == DISPLAY_SHT) {
    pretty_print_sht(&input, elf->elfh, elf->elfs);
    SAY("\n");
  }

  if ((option & DISPLAY_STRTAB) == DISPLAY_STRTAB) {
    pretty_print_strtab(&input, elf->elfh, elf->elfs);
    SAY("\n");
  }
  
  return SUCCESS;
}

void reverse_elf(int argc, char** argv) {
  malelf_object input;
  int opt_getopt = 0, opt = 0;
  FILE *fd_output = NULL;
  char* input_filename = NULL, *output_filename = NULL;
#define REVERSE_ELF 1
#define MOUNT_ELF 2

  while((opt_getopt = getopt(argc, argv, "hmri:o:")) != -1) {
    switch(opt_getopt) {
    case 'h':
      help_reverse_elf();
      break;
    case 'r':
      if (opt != 0) {
        LOG_ERROR("-m OR -r is granted, not both.\n");
        help_reverse_elf();
        exit(1);
      }
      opt = REVERSE_ELF;
      break;
    case 'm':
      if (opt != 0) {
        LOG_ERROR("-m OR -r is granted, not both.\n");
        help_reverse_elf();
        exit(1);
      }
      opt = MOUNT_ELF;
      break;
    case 'i':
      input_filename = optarg;
      break;
    case 'o':
      output_filename = optarg;
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

  if (input_filename == NULL) {
    LOG_ERROR("-i input filename not specified.\n");
    help_reverse_elf();
    exit(1);
  }
  
  if (output_filename == NULL) {
    fd_output = stdout;
  } else {
    fd_output = fopen(output_filename, "w");
    if (!fd_output) {
      perror("Error when open file for write...");
      exit(1);
    }
  }

  if (opt == REVERSE_ELF) {
    input.fname = input_filename;
    malelf_openr(&input, input.fname);
    reverse_elf2c(&input, fd_output);
  } else {
    LOG_ERROR("-m or -r is required.\n");
    help_reverse_elf();
    exit(1);
  }

  if (output_filename && fd_output) {
    fclose(fd_output);
  }
  
  if (input.mem != NULL) {
    munmap(input.mem, input.st_info.st_size);
  }
}

void infect(int argc, char** argv) {
  int opt;
  malelf_object input, output;

  while((opt = getopt(argc, argv, "hi:o:")) != -1) {
    switch(opt) {
    case 'h':
      help_infect();
      break;
    case 'i':
      input.fname = optarg;
      break;
    case 'o':
      output.fname = optarg;
      break;
    case ':':
      LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
      help_infect();
      break;
    case '?':
      LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
      help_infect();
    }
  }

  if (input.fname == NULL) {
    help_infect();
    exit(1);
  }

  if (output.fname == NULL) {
    help_infect();
    exit(1);
  }

  malelf_openr(&input, input.fname);
  /*create_elf_file(&output);*/
  input.is_readonly = 1;
  malelf_infect(&input, &output);
}

void disas(int argc, char** argv) {
    int opt;
    malelf_object input;
    char* out_fname = NULL;
    FILE* outfd;

    input.fname = NULL;

    while((opt = getopt(argc, argv, "hi:o:")) != -1) {
      switch(opt) {
      case 'h':
        help_disas();
        break;
      case 'i':
        input.fname = optarg;
        break;
      case 'o':
        out_fname = optarg;
        break;
      case ':':
        LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
        help_infect();
        break;
      case '?':
        LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
        help_disas();
      }
    }

    if (input.fname == NULL) {
      help_disas();
      exit(1);
    }

    if (out_fname == NULL) {
      outfd = stdout;
    } else {
        outfd = fopen(out_fname, "w");
        if (!outfd) {
          perror("Error when open file for write...");
          exit(1);
        }
    }

    input.is_readonly = 1;
    malelf_openr(&input, input.fname);

    malelf_disas(&input, outfd);
}

int
main(int argc, char **argv) {

  if(argc == 1) {
    LOG_WARN("This program needs arguments....\n\n");
    help(1);
  }

  if (!strcmp("-h", argv[1])) {
    help();
  }  else if (!strcmp("dissect", argv[1])) {
    dissect(argc, argv);
  } else if (!strcmp("entry_point", argv[1])) {
    entry_point(argc, argv);
  } else if (!strcmp("reverse_elf", argv[1])) {
    reverse_elf(argc, argv);
  } else if (!strcmp("infect", argv[1])) {
    infect(argc, argv);
  } else if (!strcmp("copy", argv[1])) {
    copy(argc, argv);
  } else if(!strcmp("disas", argv[1])) {
      disas(argc, argv);
  } else help();

  return 0;
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
  SAY(" \tdissect\n");
  SAY(" \treverse_elf\n");
  SAY(" \tdisas\n");
  SAY(" \tentry_point\n");
  SAY(" \tinfect\n");
  SAY(" \tcopy\n");
  
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
  SAY("./malelficus dissect [-hvepsS] -i <input file>\n");
  SAY("\tThis command display information about the ELF binary\n\n");
  SAY(" -h\tdissect help\n");
  SAY(" -i <file>\t Input binary file\n");
  SAY(" -e\tDisplay ELF Header Table\n");
  SAY(" -p\tDisplay Program Header Table\n");
  SAY(" -s\tDisplay Section Header Table\n");
  SAY(" -S\tDisplay Symbol Table\n");
  exit(SUCCESS);
}

void help_reverse_elf() {
  SAY("Reverse ELF binary\n");
  SAY("./malelficus reverse_elf [-h] -i <input file> [,-o <output-file>]\n");
  SAY("\tThis command reverse the ELF binary image in the C structs representation.\n");
  SAY("\tIt will provide the chance of manual edit the binary image.\n");
  SAY(" -h\treverse_elf help\n");
  SAY(" -i <file>\tInput binary/source file\n");
  SAY(" -o <file>\tOutput binary/C file\n");
  SAY(" -r Reverse the ELF binary into your C-structures.\n");
  SAY(" -m Mount the C file representarion of the binary into binary\n");
  exit(SUCCESS);
}

void help_infect() {
  SAY("Infect ELF binary\n");
  SAY("./malelficus infect [-h] -m <algo> -i <input-binary> [,-o <output-infected-binary>]\n");
  SAY("\tThis command tries to infect a binary using.\n");
  SAY("\tthe method passed in -m\n");
  SAY(" -h\tinfect help\n");
  SAY(" -m\tInfect methods:\n");
  SAY(" \t\tsilvio\t\tSilvio Cesare technique\n");
  SAY(" -i <binary>\tInput binary file\n");
  SAY(" -o <output-binary>\tOutput infected file\n");
  exit(SUCCESS);
  
}

void help_copy() {
  SAY("Copy ELF binary\n");
  SAY("./malelficus copy [-h] -i <input-binary> -o <output-binary>]\n");
  SAY("\tCopy binary ELF.\n");
  SAY("\tthe method passed in -m\n");
  SAY(" -h\tinfect help\n");
  SAY(" -i <binary>\tInput binary file\n");
  SAY(" -o <output-binary>\tOutput file\n");
  exit(SUCCESS);
}

void help_disas() {
  SAY("Disassembly ELF binary\n");
  SAY("./malelficus disas [-h] -i <input-binary> [-o <output-asm>]\n");
  SAY("\tDisassembly binary ELF in NASM compatible format.\n");
  SAY(" -h\tdisas help\n");
  SAY(" -i <binary>\tInput binary file\n");
  SAY(" -o <output-asm>\tOutput file, default is stdout\n");
  exit(SUCCESS);
}
