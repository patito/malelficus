#include <elf.h>

Elf32_Ehdr elf_header = {
/* 000000 */	"\x7f\x45\x4c\x46\x1\x1\x1\x0\x0\x0\x0\x0\x0\x0\x0\x0",
/* 000010 */	2,	/* Executable file  */
/* 000012 */	3,	/* EM_386 */
/* 000014 */	1,	/* CURRENT VERSION */
/* 000018 */	0x8048320,	/* Entry point */
/* 00001c */	0x34,	/* Program Header Table file offset */
/* 000020 */	0x113c,	/* Section Header Table file offset */
/* 000024 */	0,	/* Processor Spacefic-Flags */
/* 000028 */	52,	/* ELF Header size in bytes */
/* 00002a */	32,	/* Program Header Table entry size */
/* 00002c */	9,	/* Program Header Table entry count */
/* 00002e */	40,	/* Section Header Table entry size */
/* 000030 */	30,	/* Section Header Table entry size */
/* 000032 */	27	/* Section Header string table index */
};

Elf32_Phdr pht[9] = {
{
/* 000034 */	0x62696c2f,	/* UNKNOWN */
/* 000038 */	0x0,	/* Segment file offset  */
/* 00003c */	0x0,	/* Segment virtual address */
/* 000040 */	0x0,	/* Segment physical address  */
/* 000044 */	0,	/* Segment size in file */
/* 000048 */	0,	/* Segment size in memory */
/* 00004c */	0,	/* Segment flags */
/* 000050 */	0,	/* Segment alignment */
},
{
/* 000054 */	0x0,	/* PT_NULL */
/* 000058 */	0x0,	/* Segment file offset  */
/* 00005c */	0x0,	/* Segment virtual address */
/* 000060 */	0x1b,	/* Segment physical address  */
/* 000064 */	1,	/* Segment size in file */
/* 000068 */	2,	/* Segment size in memory */
/* 00006c */	134512980,	/* Segment flags */
/* 000070 */	340,	/* Segment alignment */
},
{
/* 000074 */	0x13,	/* UNKNOWN */
/* 000078 */	0x0,	/* Segment file offset  */
/* 00007c */	0x0,	/* Segment virtual address */
/* 000080 */	0x1,	/* Segment physical address  */
/* 000084 */	0,	/* Segment size in file */
/* 000088 */	35,	/* Segment size in memory */
/* 00008c */	7,	/* Segment flags */
/* 000090 */	2,	/* Segment alignment */
},
{
/* 000094 */	0x8048168,	/* UNKNOWN */
/* 000098 */	0x168,	/* Segment file offset  */
/* 00009c */	0x20,	/* Segment virtual address */
/* 0000a0 */	0x0,	/* Segment physical address  */
/* 0000a4 */	0,	/* Segment size in file */
/* 0000a8 */	4,	/* Segment size in memory */
/* 0000ac */	0,	/* Segment flags */
/* 0000b0 */	49,	/* Segment alignment */
},
{
/* 0000b4 */	0x7,	/* PT_TLS */
/* 0000b8 */	0x2,	/* Segment file offset  */
/* 0000bc */	0x8048188,	/* Segment virtual address */
/* 0000c0 */	0x188,	/* Segment physical address  */
/* 0000c4 */	36,	/* Segment size in file */
/* 0000c8 */	0,	/* Segment size in memory */
/* 0000cc */	0,	/* Segment flags */
/* 0000d0 */	4,	/* Segment alignment */
},
{
/* 0000d4 */	0x0,	/* PT_NULL */
/* 0000d8 */	0x44,	/* Segment file offset  */
/* 0000dc */	0x6ffffff6,	/* Segment virtual address */
/* 0000e0 */	0x2,	/* Segment physical address  */
/* 0000e4 */	134513068,	/* Segment size in file */
/* 0000e8 */	428,	/* Segment size in memory */
/* 0000ec */	32,	/* Segment flags */
/* 0000f0 */	5,	/* Segment alignment */
},
{
/* 0000f4 */	0x0,	/* PT_NULL */
/* 0000f8 */	0x4,	/* Segment file offset  */
/* 0000fc */	0x4,	/* Segment virtual address */
/* 000100 */	0x4e,	/* Segment physical address  */
/* 000104 */	11,	/* Segment size in file */
/* 000108 */	2,	/* Segment size in memory */
/* 00010c */	134513100,	/* Segment flags */
/* 000110 */	460,	/* Segment alignment */
},
{
/* 000114 */	0x50,	/* UNKNOWN */
/* 000118 */	0x6,	/* Segment file offset  */
/* 00011c */	0x1,	/* Segment virtual address */
/* 000120 */	0x4,	/* Segment physical address  */
/* 000124 */	16,	/* Segment size in file */
/* 000128 */	86,	/* Segment size in memory */
/* 00012c */	3,	/* Segment flags */
/* 000130 */	2,	/* Segment alignment */
},
{
/* 000134 */	0x804821c,	/* UNKNOWN */
/* 000138 */	0x21c,	/* Segment file offset  */
/* 00013c */	0x4a,	/* Segment virtual address */
/* 000140 */	0x0,	/* Segment physical address  */
/* 000144 */	0,	/* Segment size in file */
/* 000148 */	1,	/* Segment size in memory */
/* 00014c */	0,	/* Segment flags */
/* 000150 */	94,	/* Segment alignment */
}};

const unsigned char* segments = 
;

Elf32_Shdr sht[30] = {
{
/* Section:  */
/* 000154 */	9,	/* Section name (string tbl index) */
/* 000158 */	0x0,	/* SHT_NULL */
/* 00015c */	0x0,	/* Section flags */
/* 000160 */	0x0,	/* Section virtual addr at execution */
/* 000164 */	0x0,	/* Section file offset */
/* 000168 */	0,	/* Section size in bytes */
/* 00016c */	0,	/* Link to another section */
/* 000170 */	0,	/* Additional section information */
/* 000174 */	0,	/* Section alignment  */
/* 000178 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00017c */	0,	/* Section name (string tbl index) */
/* 000180 */	0x0,	/* SHT_NULL */
/* 000184 */	0x0,	/* Section flags */
/* 000188 */	0x0,	/* Section virtual addr at execution */
/* 00018c */	0x0,	/* Section file offset */
/* 000190 */	0,	/* Section size in bytes */
/* 000194 */	0,	/* Link to another section */
/* 000198 */	0,	/* Additional section information */
/* 00019c */	0,	/* Section alignment  */
/* 0001a0 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0001a4 */	0,	/* Section name (string tbl index) */
/* 0001a8 */	0x0,	/* SHT_NULL */
/* 0001ac */	0x0,	/* Section flags */
/* 0001b0 */	0x0,	/* Section virtual addr at execution */
/* 0001b4 */	0x0,	/* Section file offset */
/* 0001b8 */	0,	/* Section size in bytes */
/* 0001bc */	0,	/* Link to another section */
/* 0001c0 */	0,	/* Additional section information */
/* 0001c4 */	0,	/* Section alignment  */
/* 0001c8 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0001cc */	0,	/* Section name (string tbl index) */
/* 0001d0 */	0x0,	/* SHT_NULL */
/* 0001d4 */	0x0,	/* Section flags */
/* 0001d8 */	0x0,	/* Section virtual addr at execution */
/* 0001dc */	0x0,	/* Section file offset */
/* 0001e0 */	0,	/* Section size in bytes */
/* 0001e4 */	0,	/* Link to another section */
/* 0001e8 */	0,	/* Additional section information */
/* 0001ec */	0,	/* Section alignment  */
/* 0001f0 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0001f4 */	0,	/* Section name (string tbl index) */
/* 0001f8 */	0x0,	/* SHT_NULL */
/* 0001fc */	0x0,	/* Section flags */
/* 000200 */	0x0,	/* Section virtual addr at execution */
/* 000204 */	0x0,	/* Section file offset */
/* 000208 */	0,	/* Section size in bytes */
/* 00020c */	0,	/* Link to another section */
/* 000210 */	0,	/* Additional section information */
/* 000214 */	0,	/* Section alignment  */
/* 000218 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00021c */	0,	/* Section name (string tbl index) */
/* 000220 */	0x0,	/* SHT_NULL */
/* 000224 */	0x0,	/* Section flags */
/* 000228 */	0x0,	/* Section virtual addr at execution */
/* 00022c */	0x0,	/* Section file offset */
/* 000230 */	0,	/* Section size in bytes */
/* 000234 */	0,	/* Link to another section */
/* 000238 */	0,	/* Additional section information */
/* 00023c */	0,	/* Section alignment  */
/* 000240 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000244 */	0,	/* Section name (string tbl index) */
/* 000248 */	0x0,	/* SHT_NULL */
/* 00024c */	0x0,	/* Section flags */
/* 000250 */	0x0,	/* Section virtual addr at execution */
/* 000254 */	0x0,	/* Section file offset */
/* 000258 */	0,	/* Section size in bytes */
/* 00025c */	0,	/* Link to another section */
/* 000260 */	0,	/* Additional section information */
/* 000264 */	0,	/* Section alignment  */
/* 000268 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00026c */	0,	/* Section name (string tbl index) */
/* 000270 */	0x0,	/* SHT_NULL */
/* 000274 */	0x0,	/* Section flags */
/* 000278 */	0x0,	/* Section virtual addr at execution */
/* 00027c */	0x0,	/* Section file offset */
/* 000280 */	0,	/* Section size in bytes */
/* 000284 */	0,	/* Link to another section */
/* 000288 */	0,	/* Additional section information */
/* 00028c */	0,	/* Section alignment  */
/* 000290 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000294 */	0,	/* Section name (string tbl index) */
/* 000298 */	0x0,	/* SHT_NULL */
/* 00029c */	0x0,	/* Section flags */
/* 0002a0 */	0x0,	/* Section virtual addr at execution */
/* 0002a4 */	0x0,	/* Section file offset */
/* 0002a8 */	0,	/* Section size in bytes */
/* 0002ac */	0,	/* Link to another section */
/* 0002b0 */	0,	/* Additional section information */
/* 0002b4 */	0,	/* Section alignment  */
/* 0002b8 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0002bc */	0,	/* Section name (string tbl index) */
/* 0002c0 */	0x0,	/* SHT_NULL */
/* 0002c4 */	0x0,	/* Section flags */
/* 0002c8 */	0x0,	/* Section virtual addr at execution */
/* 0002cc */	0x0,	/* Section file offset */
/* 0002d0 */	0,	/* Section size in bytes */
/* 0002d4 */	0,	/* Link to another section */
/* 0002d8 */	0,	/* Additional section information */
/* 0002dc */	0,	/* Section alignment  */
/* 0002e0 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0002e4 */	0,	/* Section name (string tbl index) */
/* 0002e8 */	0x0,	/* SHT_NULL */
/* 0002ec */	0x0,	/* Section flags */
/* 0002f0 */	0x0,	/* Section virtual addr at execution */
/* 0002f4 */	0x0,	/* Section file offset */
/* 0002f8 */	0,	/* Section size in bytes */
/* 0002fc */	0,	/* Link to another section */
/* 000300 */	0,	/* Additional section information */
/* 000304 */	0,	/* Section alignment  */
/* 000308 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00030c */	0,	/* Section name (string tbl index) */
/* 000310 */	0x0,	/* SHT_NULL */
/* 000314 */	0x0,	/* Section flags */
/* 000318 */	0x0,	/* Section virtual addr at execution */
/* 00031c */	0x0,	/* Section file offset */
/* 000320 */	0,	/* Section size in bytes */
/* 000324 */	0,	/* Link to another section */
/* 000328 */	0,	/* Additional section information */
/* 00032c */	0,	/* Section alignment  */
/* 000330 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000334 */	0,	/* Section name (string tbl index) */
/* 000338 */	0x0,	/* SHT_NULL */
/* 00033c */	0x0,	/* Section flags */
/* 000340 */	0x0,	/* Section virtual addr at execution */
/* 000344 */	0x0,	/* Section file offset */
/* 000348 */	0,	/* Section size in bytes */
/* 00034c */	0,	/* Link to another section */
/* 000350 */	0,	/* Additional section information */
/* 000354 */	0,	/* Section alignment  */
/* 000358 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00035c */	0,	/* Section name (string tbl index) */
/* 000360 */	0x0,	/* SHT_NULL */
/* 000364 */	0x0,	/* Section flags */
/* 000368 */	0x0,	/* Section virtual addr at execution */
/* 00036c */	0x0,	/* Section file offset */
/* 000370 */	0,	/* Section size in bytes */
/* 000374 */	0,	/* Link to another section */
/* 000378 */	0,	/* Additional section information */
/* 00037c */	0,	/* Section alignment  */
/* 000380 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000384 */	0,	/* Section name (string tbl index) */
/* 000388 */	0x0,	/* SHT_NULL */
/* 00038c */	0x0,	/* Section flags */
/* 000390 */	0x0,	/* Section virtual addr at execution */
/* 000394 */	0x0,	/* Section file offset */
/* 000398 */	0,	/* Section size in bytes */
/* 00039c */	0,	/* Link to another section */
/* 0003a0 */	0,	/* Additional section information */
/* 0003a4 */	0,	/* Section alignment  */
/* 0003a8 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0003ac */	0,	/* Section name (string tbl index) */
/* 0003b0 */	0x0,	/* SHT_NULL */
/* 0003b4 */	0x0,	/* Section flags */
/* 0003b8 */	0x0,	/* Section virtual addr at execution */
/* 0003bc */	0x0,	/* Section file offset */
/* 0003c0 */	0,	/* Section size in bytes */
/* 0003c4 */	0,	/* Link to another section */
/* 0003c8 */	0,	/* Additional section information */
/* 0003cc */	0,	/* Section alignment  */
/* 0003d0 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0003d4 */	0,	/* Section name (string tbl index) */
/* 0003d8 */	0x0,	/* SHT_NULL */
/* 0003dc */	0x0,	/* Section flags */
/* 0003e0 */	0x0,	/* Section virtual addr at execution */
/* 0003e4 */	0x0,	/* Section file offset */
/* 0003e8 */	0,	/* Section size in bytes */
/* 0003ec */	0,	/* Link to another section */
/* 0003f0 */	0,	/* Additional section information */
/* 0003f4 */	0,	/* Section alignment  */
/* 0003f8 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0003fc */	0,	/* Section name (string tbl index) */
/* 000400 */	0x0,	/* SHT_NULL */
/* 000404 */	0x0,	/* Section flags */
/* 000408 */	0x0,	/* Section virtual addr at execution */
/* 00040c */	0x0,	/* Section file offset */
/* 000410 */	0,	/* Section size in bytes */
/* 000414 */	0,	/* Link to another section */
/* 000418 */	0,	/* Additional section information */
/* 00041c */	0,	/* Section alignment  */
/* 000420 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000424 */	0,	/* Section name (string tbl index) */
/* 000428 */	0x0,	/* SHT_NULL */
/* 00042c */	0x0,	/* Section flags */
/* 000430 */	0x0,	/* Section virtual addr at execution */
/* 000434 */	0x0,	/* Section file offset */
/* 000438 */	0,	/* Section size in bytes */
/* 00043c */	0,	/* Link to another section */
/* 000440 */	0,	/* Additional section information */
/* 000444 */	0,	/* Section alignment  */
/* 000448 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00044c */	0,	/* Section name (string tbl index) */
/* 000450 */	0x0,	/* SHT_NULL */
/* 000454 */	0x0,	/* Section flags */
/* 000458 */	0x0,	/* Section virtual addr at execution */
/* 00045c */	0x0,	/* Section file offset */
/* 000460 */	0,	/* Section size in bytes */
/* 000464 */	0,	/* Link to another section */
/* 000468 */	0,	/* Additional section information */
/* 00046c */	0,	/* Section alignment  */
/* 000470 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000474 */	0,	/* Section name (string tbl index) */
/* 000478 */	0x0,	/* SHT_NULL */
/* 00047c */	0x0,	/* Section flags */
/* 000480 */	0x0,	/* Section virtual addr at execution */
/* 000484 */	0x0,	/* Section file offset */
/* 000488 */	0,	/* Section size in bytes */
/* 00048c */	0,	/* Link to another section */
/* 000490 */	0,	/* Additional section information */
/* 000494 */	0,	/* Section alignment  */
/* 000498 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00049c */	0,	/* Section name (string tbl index) */
/* 0004a0 */	0x0,	/* SHT_NULL */
/* 0004a4 */	0x0,	/* Section flags */
/* 0004a8 */	0x0,	/* Section virtual addr at execution */
/* 0004ac */	0x0,	/* Section file offset */
/* 0004b0 */	0,	/* Section size in bytes */
/* 0004b4 */	0,	/* Link to another section */
/* 0004b8 */	0,	/* Additional section information */
/* 0004bc */	0,	/* Section alignment  */
/* 0004c0 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0004c4 */	0,	/* Section name (string tbl index) */
/* 0004c8 */	0x0,	/* SHT_NULL */
/* 0004cc */	0x0,	/* Section flags */
/* 0004d0 */	0x0,	/* Section virtual addr at execution */
/* 0004d4 */	0x0,	/* Section file offset */
/* 0004d8 */	0,	/* Section size in bytes */
/* 0004dc */	0,	/* Link to another section */
/* 0004e0 */	0,	/* Additional section information */
/* 0004e4 */	0,	/* Section alignment  */
/* 0004e8 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0004ec */	0,	/* Section name (string tbl index) */
/* 0004f0 */	0x0,	/* SHT_NULL */
/* 0004f4 */	0x0,	/* Section flags */
/* 0004f8 */	0x0,	/* Section virtual addr at execution */
/* 0004fc */	0x0,	/* Section file offset */
/* 000500 */	0,	/* Section size in bytes */
/* 000504 */	0,	/* Link to another section */
/* 000508 */	0,	/* Additional section information */
/* 00050c */	0,	/* Section alignment  */
/* 000510 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000514 */	0,	/* Section name (string tbl index) */
/* 000518 */	0x0,	/* SHT_NULL */
/* 00051c */	0x0,	/* Section flags */
/* 000520 */	0x0,	/* Section virtual addr at execution */
/* 000524 */	0x0,	/* Section file offset */
/* 000528 */	0,	/* Section size in bytes */
/* 00052c */	0,	/* Link to another section */
/* 000530 */	0,	/* Additional section information */
/* 000534 */	0,	/* Section alignment  */
/* 000538 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00053c */	0,	/* Section name (string tbl index) */
/* 000540 */	0x0,	/* SHT_NULL */
/* 000544 */	0x0,	/* Section flags */
/* 000548 */	0x0,	/* Section virtual addr at execution */
/* 00054c */	0x0,	/* Section file offset */
/* 000550 */	0,	/* Section size in bytes */
/* 000554 */	0,	/* Link to another section */
/* 000558 */	0,	/* Additional section information */
/* 00055c */	0,	/* Section alignment  */
/* 000560 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 000564 */	0,	/* Section name (string tbl index) */
/* 000568 */	0x0,	/* SHT_NULL */
/* 00056c */	0x0,	/* Section flags */
/* 000570 */	0x0,	/* Section virtual addr at execution */
/* 000574 */	0x0,	/* Section file offset */
/* 000578 */	0,	/* Section size in bytes */
/* 00057c */	0,	/* Link to another section */
/* 000580 */	0,	/* Additional section information */
/* 000584 */	0,	/* Section alignment  */
/* 000588 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 00058c */	0,	/* Section name (string tbl index) */
/* 000590 */	0x0,	/* SHT_NULL */
/* 000594 */	0x0,	/* Section flags */
/* 000598 */	0x0,	/* Section virtual addr at execution */
/* 00059c */	0x0,	/* Section file offset */
/* 0005a0 */	0,	/* Section size in bytes */
/* 0005a4 */	0,	/* Link to another section */
/* 0005a8 */	0,	/* Additional section information */
/* 0005ac */	0,	/* Section alignment  */
/* 0005b0 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0005b4 */	0,	/* Section name (string tbl index) */
/* 0005b8 */	0x0,	/* SHT_NULL */
/* 0005bc */	0x0,	/* Section flags */
/* 0005c0 */	0x0,	/* Section virtual addr at execution */
/* 0005c4 */	0x0,	/* Section file offset */
/* 0005c8 */	0,	/* Section size in bytes */
/* 0005cc */	0,	/* Link to another section */
/* 0005d0 */	0,	/* Additional section information */
/* 0005d4 */	0,	/* Section alignment  */
/* 0005d8 */	0,	/* Entry size if section holds table */
},
{
/* Section: ELF */
/* 0005dc */	0,	/* Section name (string tbl index) */
/* 0005e0 */	0x0,	/* SHT_NULL */
/* 0005e4 */	0x0,	/* Section flags */
/* 0005e8 */	0x0,	/* Section virtual addr at execution */
/* 0005ec */	0x0,	/* Section file offset */
/* 0005f0 */	0,	/* Section size in bytes */
/* 0005f4 */	0,	/* Link to another section */
/* 0005f8 */	0,	/* Additional section information */
/* 0005fc */	0,	/* Section alignment  */
/* 000600 */	0,	/* Entry size if section holds table */
}};

;

