/*
   Malelficus
   --------

   MalELFicus is malefic tool for dissect and infect ELF binaries.
   Please do not be malefic to use this tool.

   Author: Tiago Natel de Moura <tiago4orion@gmail.com>

   Copyright 2010, 2011 by Tiago Natel de Moura. All Rights Reserved.

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
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#define E_ENTRY 0x01
#define E_HEADERS 0x02
#define E_SECTIONS 0x04

#define EXIT_ERROR 1
#define LOG_RAW(out, format...) fprintf(out, format)
#define SAY(format...) LOG_RAW(stdout, format)
#define LOG(format...) LOG_RAW(stdout, "[+] " format)
#define LOG_ERROR(format...) LOG_RAW(stderr, "[-] ERROR: " format); exit(EXIT_ERROR)
#define LOG_WARN(format...) LOG_RAW(stderr, "[-] WARNING: " format)
#define LOG_OFFSET(desc_format, value) if (quiet_mode) { LOG_RAW(stdout, "0x%x", value); } else LOG_RAW(stdout, desc_format, value)

typedef uint8_t _u8;
typedef uint16_t _u16;
typedef uint32_t _u32;
typedef int8_t _i8;
typedef int16_t _i16;
typedef int32_t _i32;

void print_help(int);
void read_file(char*);
void get_entry_point();
void check_elf();
void elf_dissect(const char*, unsigned int);

int fd, quiet_mode = 0;
unsigned char *mem;
struct stat st;

int main(int argc, char **argv) {
  unsigned int elf_option = 0x0;
  char* elf_file = NULL;
  int opt;

  if(argc == 1) {
    LOG_WARN("This program needs arguments....\n\n");
    print_help(1);
  }

  while((opt = getopt(argc, argv, "hqevf:")) != -1) {
    switch(opt) {
    case 'h':
      print_help(0);
      break;
    case 'q':
      quiet_mode = 0x01;
      break;
    case 'f':
      elf_file = optarg;
      break;
    case 'e':
      elf_option |= E_ENTRY;
      break;
    case ':':
      LOG_WARN("malelf: Error - Option `%c' needs a value\n\n", optopt);
      print_help(1);
      break;
    case '?':
      LOG_WARN("malelf: Error - No such option: `%c'\n\n", optopt);
      print_help(1);
    }
  }

  /* 
  // print all remaining options
  */
  for(; optind < argc; optind++)
    printf("argument: %s\n", argv[optind]);

  read_file(elf_file);
  check_elf();

  if (elf_option & E_ENTRY) {
    get_entry_point();
  }
	
  return 0;
}


void print_help(int exval) {
  const  _u8* banner = (_u8*)
#include "malelficus_banner.h"
    ;

  printf("%s\n", banner); 
  printf("malelf [-heqv] [-f FILE] [-o FILE]\n\n");

  printf("  -h              print this help and exit\n");
  printf("  -e              print entry point\n\n");

  printf("  -v              set verbose flag\n");
  printf("  -q              quiet mode\n");
  printf("  -f FILE         set intput file\n");
  printf("  -o FILE         set output file\n\n");

  exit(exval);
}

void read_file(char* elf_file) {
  fd = open(elf_file, O_RDWR | O_FSYNC);

  if (fd == -1) {
    LOG_ERROR("Erro ao abrir arquivo!\n");
    exit(1);
  }

  fstat(fd, &st);

  mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	
  if (mem == MAP_FAILED) {
    LOG_ERROR("mmap falhou!\n");
    exit(1);
  }
}

void check_elf() {
  Elf32_Ehdr *header;

  header = (Elf32_Ehdr*)mem;

  if (!header) {
    LOG_ERROR("file not mapped to memory.\n");
  }

  if (header->e_ident[0] == ELFMAG[0] && header->e_ident[1] == ELFMAG[1]
      && header->e_ident[2] == ELFMAG[2] && header->e_ident[3] == ELFMAG[3]) {
    if (!quiet_mode) {
      LOG("Valid ELF file\n");
    }
  } else {
      LOG_ERROR("Not a valid ELF\n");
    }
}

void get_entry_point() {
  Elf32_Ehdr *header = NULL;

  header = (Elf32_Ehdr*)mem;

  if (!header) {
    LOG_ERROR("file not mapped to memory.\n");
  }
  
  LOG_OFFSET("Entry point: 0x%x\n", header->e_entry);
}

void get_sections() {

}

#if 0
void elf_dissect(const char* elf_file, unsigned int elf_option) {
  Elf32_Ehdr *header;
  Elf32_Phdr *pheaders;
  Elf32_Shdr *sections;
  int i;
  	
  header = (Elf32_Ehdr*) mem;

  /* Checa a assinatura do ELF */
  if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
    printf("Não possui a assinatura de um ELF!\n");
    exit(1);
  }

  pheaders = (Elf32_Phdr*) (mem + header->e_phoff);
  sections = (Elf32_Shdr*) (mem + header->e_shoff);

  printf("ident: %c%c%c\n", header->e_ident[1],header->e_ident[2],header->e_ident[3]);
  printf("Entry point: 0x%x\n", header->e_entry);
  printf("Número de seções: %hd\n", header->e_shnum);
    
  printf("HEADERS:\n");
  for (i = 0; i < header->e_phnum; ++i) {
    printf("Offset: 0x%x\n", ((Elf32_Phdr*)(pheaders + i))->p_offset);
  }

  printf("SECTIONS: \n");

  for (i = 0; i < header->e_shnum; ++i) {
    printf("[%d] Offset: 0x%x, name = %s\n", i, ((Elf32_Shdr*)(sections + i))->sh_addr, mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name);
  }
	
  munmap(mem, st.st_size);
  close(fd);
}

#endif
