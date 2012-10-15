#ifndef DATABASE_H
#define DATABASE_H

#include <stdio.h>
#include <malelf/types.h>

_i32 create_section_database(const char* scan_file, FILE* outfd, _u32* n_items);
_i32 update_section_database(const char* scan_file, FILE* outfd, _u32* n_items);
_u8 in_database(FILE* database, char* sect_name, char* sect_type);

#endif
