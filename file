#include <elf.h>

Elf32_Ehdr elf_header = {
/* 000000 */	"\x7f\x45\x4c\x46\x1\x1\x1\x0\x0\x0\x0\x0\x0\x0\x0\x0",
/* 000010 */	2,	/* Executable file  */
/* 000012 */	3,	/* EM_386 */
/* 000014 */	1,	/* CURRENT VERSION */
/* 000018 */	0x8048580,	/* Entry point */
/* 00001c */	0x34,	/* Program Header Table file offset */
/* 000020 */	0x12b8,	/* Section Header Table file offset */
/* 000024 */	0,	/* Processor Spacefic-Flags */
/* 000028 */	52,	/* ELF Header size in bytes */
/* 00002a */	32,	/* Program Header Table entry size */
/* 00002c */	9,	/* Program Header Table entry count */
/* 00002e */	40,	/* Section Header Table entry size */
/* 000030 */	30,	/* Section Header Table entry size */
/* 000032 */	27	/* Section Header string table index */
};

Elf32_Phdr pht = {
{
/* 000034 */	0x6,	/* PT_PHDR */
/* 000038 */	0x34,	/* Segment file offset  */
/* 00003c */	0x8048034,	/* Segment virtual address */
/* 000040 */	0x8048034,	/* Segment physical address  */
/* 000044 */	288,	/* Segment size in file */
/* 000048 */	288,	/* Segment size in memory */
/* 00004c */	5,	/* Segment flags */
/* 000050 */	4,	/* Segment alignment */
},
{
/* 000054 */	0x3,	/* PT_INTERP */
/* 000058 */	0x154,	/* Segment file offset  */
/* 00005c */	0x8048154,	/* Segment virtual address */
/* 000060 */	0x8048154,	/* Segment physical address  */
/* 000064 */	19,	/* Segment size in file */
/* 000068 */	19,	/* Segment size in memory */
/* 00006c */	4,	/* Segment flags */
/* 000070 */	1,	/* Segment alignment */
},
{
/* 000074 */	0x1,	/* PT_LOAD */
/* 000078 */	0x0,	/* Segment file offset  */
/* 00007c */	0x8048000,	/* Segment virtual address */
/* 000080 */	0x8048000,	/* Segment physical address  */
/* 000084 */	3740,	/* Segment size in file */
/* 000088 */	3740,	/* Segment size in memory */
/* 00008c */	5,	/* Segment flags */
/* 000090 */	4096,	/* Segment alignment */
},
{
/* 000094 */	0x1,	/* PT_LOAD */
/* 000098 */	0xf14,	/* Segment file offset  */
/* 00009c */	0x8049f14,	/* Segment virtual address */
/* 0000a0 */	0x8049f14,	/* Segment physical address  */
/* 0000a4 */	636,	/* Segment size in file */
/* 0000a8 */	648,	/* Segment size in memory */
/* 0000ac */	6,	/* Segment flags */
/* 0000b0 */	4096,	/* Segment alignment */
},
{
/* 0000b4 */	0x2,	/* PT_DYNAMIC */
/* 0000b8 */	0xf28,	/* Segment file offset  */
/* 0000bc */	0x8049f28,	/* Segment virtual address */
/* 0000c0 */	0x8049f28,	/* Segment physical address  */
/* 0000c4 */	200,	/* Segment size in file */
/* 0000c8 */	200,	/* Segment size in memory */
/* 0000cc */	6,	/* Segment flags */
/* 0000d0 */	4,	/* Segment alignment */
},
{
/* 0000d4 */	0x4,	/* PT_NOTE */
/* 0000d8 */	0x168,	/* Segment file offset  */
/* 0000dc */	0x8048168,	/* Segment virtual address */
/* 0000e0 */	0x8048168,	/* Segment physical address  */
/* 0000e4 */	68,	/* Segment size in file */
/* 0000e8 */	68,	/* Segment size in memory */
/* 0000ec */	4,	/* Segment flags */
/* 0000f0 */	4,	/* Segment alignment */
},
{
/* 0000f4 */	0x6474e550,	/* PT_GNU_EH_FRAME */
/* 0000f8 */	0xd04,	/* Segment file offset  */
/* 0000fc */	0x8048d04,	/* Segment virtual address */
/* 000100 */	0x8048d04,	/* Segment physical address  */
/* 000104 */	84,	/* Segment size in file */
/* 000108 */	84,	/* Segment size in memory */
/* 00010c */	4,	/* Segment flags */
/* 000110 */	4,	/* Segment alignment */
},
{
/* 000114 */	0x6474e551,	/* PT_GNU_STACK */
/* 000118 */	0x0,	/* Segment file offset  */
/* 00011c */	0x0,	/* Segment virtual address */
/* 000120 */	0x0,	/* Segment physical address  */
/* 000124 */	0,	/* Segment size in file */
/* 000128 */	0,	/* Segment size in memory */
/* 00012c */	6,	/* Segment flags */
/* 000130 */	4,	/* Segment alignment */
},
{
/* 000134 */	0x6474e552,	/* PT_GNU_RELRO */
/* 000138 */	0xf14,	/* Segment file offset  */
/* 00013c */	0x8049f14,	/* Segment virtual address */
/* 000140 */	0x8049f14,	/* Segment physical address  */
/* 000144 */	236,	/* Segment size in file */
/* 000148 */	236,	/* Segment size in memory */
/* 00014c */	4,	/* Segment flags */
/* 000150 */	1,	/* Segment alignment */
}
