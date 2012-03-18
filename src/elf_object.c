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

#include "defines.h"
#include "elf_object.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
