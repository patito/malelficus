#ifndef ANALYSE_H
#define ANALYSE_H

#include <malelf/types.h>
#include <malelf/object.h>
#include <malelf/error.h>

struct suspect_sect_arg {
    char* sect_name_target;
    char* sect_type_target;
    FILE* database_fd;
};

_i32 suspect_section_callback(char* sect_name, char* sect_type, void *arg);

_i32 analyse_suspect_section(malelf_object* elf_obj,
                                    char* sect_name,
                             FILE* section_fp);

    

#endif
