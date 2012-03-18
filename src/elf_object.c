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
