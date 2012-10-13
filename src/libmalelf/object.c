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
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "malelf/defines.h"
#include "malelf/util.h"
#include "malelf/types.h"
#include "malelf/error.h"
#include "malelf/object.h"
#include "malelf/dissect.h"

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

/**
 * Initialize the malelf object data type.
 * Never forget to call this function before use the malelf API
 * with malelf_object.
 *
 * @param malelf_object*
 * @return void
 */
void malelf_init_object(malelf_object* obj) {
  obj->fname = NULL;
  obj->fd = -1;
  obj->mem = NULL;
  obj->elf.elfh = NULL;
  obj->elf.elfp = NULL;
  obj->elf.elfs = NULL;
}

/**
 * Check if the binary file mapped in obj is of type ELF
 *
 * @param malelf_object*
 * @return malelf_status
 */
_u8 malelf_check_elf(malelf_object* obj) {
  _u8 valid = MALELF_SUCCESS;
  ElfW(Ehdr)* ehdr;

  if (obj == NULL || obj->mem == NULL) {
    return MALELF_ERROR;
  }
  
  ehdr = (ElfW(Ehdr)*) obj->mem;
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
    valid = MALELF_SUCCESS;
  } else {
    valid = MALELF_ERROR;
  }
  
  return valid;
}

/**
 * Open the binary file 'filename' and fill the struct malelf_object.
 * Uses mmap to map the binary in memory.
 *
 * @param malelf_object* obj
 * @param char* filename
 * @param int flags
 */
_i32 malelf_open(malelf_object* obj, char* filename, int flags) {
  _u8 is_creat = (flags & O_CREAT) == O_CREAT;
  assert(obj != NULL);
  assert(filename != NULL);
  
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
    obj->mem = mmap(0, obj->st_info.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, obj->fd, 0);
    if (obj->mem == MAP_FAILED) {
      return errno;
    }

    obj->alloc_type = ALLOC_MMAP;

    if (malelf_check_elf(obj) == MALELF_SUCCESS) {
      MALELF_MAP_ELF(obj);
    } else {
      LOG_WARN("Binary '%s' is not ELF.\n", obj->fname);
    }
  }

  return MALELF_SUCCESS;
}

_i32 malelf_openr(malelf_object* obj, char* filename) {
  obj->is_readonly = MALELF_READONLY;
  return malelf_open(obj, filename, O_RDONLY);
}

_i32 malelf_openw(malelf_object* obj, char* filename) {
  obj->is_readonly = MALELF_READWRITE;
  return malelf_open(obj, filename, O_RDWR | O_CREAT | O_TRUNC);
}

_u32 malelf_close(malelf_object* obj) {
  if (obj == NULL || obj->fd == -1) {
    return MALELF_ERROR_CLOSED;
  }
  
  if (obj->mem != MAP_FAILED) {
    munmap(obj->mem, obj->st_info.st_size);
  }

  return MALELF_SUCCESS;
}

_u8 malelf_add_section(malelf_object* input, malelf_object* output, malelf_add_section_t options) {
  int i;
  _u8 *data, size;

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
    data = input->mem + s->sh_offset;
    size = s->sh_size;
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

  if (out->is_readonly == MALELF_READONLY) {
    LOG_ERROR("output file '%s' is read-only!\n", out->fname);
    exit(1);
  }
  
  out->mem = malloc(sizeof(_u8) * in->st_info.st_size);
  if (!out->mem) {
    return MALELF_ERROR_ALLOC;
  }

  out->alloc_type = ALLOC_MALLOC;
  memcpy(out->mem, in->mem, in->st_info.st_size);
  
  return MALELF_SUCCESS;
}

_u8 copy_malelf_object(malelf_object* out, malelf_object* in) {
  _u8 err = copy_malelf_object_raw(out, in);

  if (err == MALELF_SUCCESS) {
    MALELF_MAP_ELF(out);
  }

  return err;
}

