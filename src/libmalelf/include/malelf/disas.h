#ifndef _MALELF_DISAS_
#define _MALELF_DISAS_

#include <stdio.h>
#include <sys/types.h>

#include "malelf/object.h"

extern void malelf_disas(malelf_object* input, FILE* out);

#endif
