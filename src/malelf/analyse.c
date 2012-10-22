#include <stdio.h>
#include <stdlib.h>
#include "analyse.h"
#include "database.h"

#include <malelf/dissect.h>

static _u32 number_suspect_sections = 0;

_i32 suspect_section_callback(char* sect_name, char* sect_type, void *arg) {
    struct suspect_sect_arg *arg2 = (struct suspect_sect_arg *) arg;
    _u32 type = atoi(sect_type);

    if (in_database(arg2->database_fd, sect_name, NULL) == 0) {
        number_suspect_sections++;
        LOG_WARN("Suspicious section: %s, type: %s\n", sect_name, GET_ATTR_NAME(get_section_type(type)));
    } else {
        LOG_VERBOSE_SUCCESS("Safe section: %s, type: %s\n", sect_name, GET_ATTR_NAME(get_section_type(type)));
    }

    return MALELF_SUCCESS;
}

_i32 analyse_suspect_section(malelf_object* elf_obj,
                                    char* sect_name,
                                    FILE* section_fp) {
    _i32 error;
    struct suspect_sect_arg arg;
    arg.sect_name_target = sect_name;
    arg.database_fd = section_fp;

    LOG_VERBOSE_SUCCESS("Analysing binary for suspicious sections...\n");
    error = malelf_sections_exec(elf_obj, suspect_section_callback, (void*)(&arg));

    if (error != MALELF_SUCCESS)
        return error;

    if (number_suspect_sections == 0) {
        LOG_SUCCESS("Every section name has a known name.\n");
        return MALELF_SUCCESS;
    } else {
        return MALELF_ESUSPECT_SECTIONS;
    }  
}
