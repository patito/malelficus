#ifndef INFECT_H
#define INFECT_H

#include "object.h"

#define MALELF_MAGIC_BYTES 0x31333337

extern _u8 malelf_infect_silvio_padding(malelf_object* input,
                                  malelf_object* output,
                                  malelf_object* parasite,
                                        _u32 offset_entry_point,
                                        unsigned long int magic_bytes);

extern _u8 _malelf_parasite_silvio_padding(malelf_object* in,
                                           malelf_object* out,
                                           unsigned int end_of_text,
                                           malelf_object *parasite,
                                           _u32 offset_entry_point,
                                           unsigned old_e_entry,
                                           unsigned long int magic_bytes);

#endif
