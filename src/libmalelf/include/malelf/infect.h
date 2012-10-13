#ifndef INFECT_H
#define INFECT_H

#include "object.h"

extern _u8 malelf_infect_silvio_padding(malelf_object* input,
                                  malelf_object* output,
                                  malelf_object* parasite,
                                  _u32 offset_entry_point);

extern _u8 _malelf_parasite_silvio_padding(malelf_object* in,
                                           malelf_object* out,
                                           unsigned int end_of_text,
                                           malelf_object *parasite,
                                           _u32 offset_entry_point,
                                           unsigned old_e_entry);

#endif
