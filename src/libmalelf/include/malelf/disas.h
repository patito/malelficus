#ifndef _MALELF_DISAS_
#define _MALELF_DISAS_

#include <stdio.h>
#include <sys/types.h>

#include "malelf/object.h"

extern _i32 malelf_disas(malelf_object* input, FILE* out);
extern _i32 malelf_disas_section(malelf_object *input, char *section, FILE *outfd);

#endif
