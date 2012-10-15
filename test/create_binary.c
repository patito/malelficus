#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

Elf32_Ehdr elf_header = {
/* 000000 */	"\x7f\x45\x4c\x46\x1\x1\x1\x0\x0\x0\x0\x0\x0\x0\x0\x0",
/* 000010 */	2,	/* Executable file  */
/* 000012 */	3,	/* EM_386 */
/* 000014 */	1,	/* CURRENT VERSION */
/* 000018 */	0x8048af0,	/* Entry point */
/* 00001c */	0x34,	/* Program Header Table file offset */
/* 000020 */	0x5198,	/* Section Header Table file offset */
/* 000024 */	0,	/* Processor Spacefic-Flags */
/* 000028 */	52,	/* ELF Header size in bytes */
/* 00002a */	32,	/* Program Header Table entry size */
/* 00002c */	8,	/* Program Header Table entry count */
/* 00002e */	40,	/* Section Header Table entry size */
/* 000030 */	27,	/* Section Header Table entry size */
/* 000032 */	26	/* Section Header string table index */
};

int main()
{
  int fd;
  
  fd = open("./echo", O_RDWR|O_CREAT);

  if (fd == -1) {
    fprintf(stderr, "não foi possivel abrir o arquivo,\n");
    return 1;
  }

  if (write(fd, &elf_header, sizeof(elf_header)) == sizeof(elf_header)) {
    printf("success: binary created\n");
  } else {
    printf("erro...\n");
  }
  
  return 0;
}
