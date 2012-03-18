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
