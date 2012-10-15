#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include "database.h"

#include <malelf/types.h>
#include <malelf/error.h>
#include <malelf/object.h>
#include <malelf/util.h>

_i32 create_section_database(const char* scan_file, FILE* outfd, _u32 *n_items) {
    return update_section_database(scan_file, outfd, n_items);
}

_i32 update_section_database(const char* scan_file, FILE* outfd, _u32 *n_items) {
    int i;
    struct stat st_info;
    DIR* dirp;
    struct dirent *dp;
    malelf_object elf_obj;
    ElfW(Ehdr) *header;
    ElfW(Shdr) *sections;
    char sect_name[255], sect_type[255];
    _i32 status = MALELF_SUCCESS;
    

    if (stat(scan_file, &st_info) == -1) {
        return errno;
    }

    /**
     * scan_file is a directory?
     */
    if (S_ISDIR(st_info.st_mode)) {
        LOG_SUCCESS("%s is a directory, iterating over files.\n");

        if ((dirp = opendir(scan_file)) == NULL) {
            return errno;
        }

        do {
            errno = 0;
            if ((dp = readdir(dirp)) != NULL) {
                printf("==%s\n", dp->d_name);
                if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
                    continue;
                char *path = (char*) malloc(strlen(scan_file) + strlen(dp->d_name) + 2);
                char *tmp_dir = malloc(strlen(scan_file)+1);
                bzero(path, strlen(scan_file) + strlen(dp->d_name) + 1);
                bzero(tmp_dir, strlen(scan_file) + 1);
                strncpy(tmp_dir, scan_file, strlen(scan_file));
                
                if (tmp_dir[strlen(tmp_dir) - 1] == '/')
                    tmp_dir[strlen(tmp_dir) - 1] = 0;
                
                strcat(path, tmp_dir);
                strcat(path, "/");
                strcat(path, dp->d_name);
                LOG_SUCCESS("Extracting section names from %s\n", path);
                status = update_section_database(path, outfd, n_items);
                free(path);
                free(tmp_dir);
                if (status != MALELF_SUCCESS && status != MALELF_ENOT_ELF) {
                    closedir(dirp);
                    return status;
                }
            }
        } while (dp != NULL);

        closedir(dirp);

        if (errno != 0) {
            return errno;
        } else if (status == MALELF_ENOT_ELF) {
            return MALELF_SUCCESS;
        } else {
            return status;
        }
    } else if (S_ISLNK(st_info.st_mode)) {
        LOG_WARN("File '%s' is a symbolic link. Skipping file...\n", scan_file);
        return MALELF_SUCCESS;
    } else if (!S_ISREG(st_info.st_mode)) {
        LOG_WARN("File '%s' is not a regular file. Skipping file...\n", scan_file);
        return MALELF_SUCCESS;
    }

    elf_obj.fname = (char*)scan_file;

    status = malelf_openr(&elf_obj, elf_obj.fname);
    if (status != MALELF_SUCCESS) {
        return status;
    }

    if (malelf_check_elf(&elf_obj) != MALELF_SUCCESS) {
        malelf_close(&elf_obj);
        return MALELF_ENOT_ELF;
    }

    if (elf_obj.elf.elfh == NULL ||
        elf_obj.elf.elfp == NULL ||
        elf_obj.elf.elfs == NULL) {
        malelf_close(&elf_obj);
        return MALELF_ECORRUPTED;
    }

    header = elf_obj.elf.elfh;
    sections = elf_obj.elf.elfs;

    for (i = 0; i < header->e_shnum; ++i) {
        ElfW(Shdr) *sect = (ElfW(Shdr)*)(sections + i);
        bzero(sect_name, 255);
        bzero(sect_type, 255);

        if (sect->sh_type != SHT_NULL && header->e_shstrndx != 0x00) {
            strncpy(sect_name, (char*) elf_obj.mem + sections[header->e_shstrndx].sh_offset + sections[i].sh_name, 255);
        } else {
            /* skip SHT_NULL */
            continue;
        }

        snprintf(sect_type, 255, "%d", sect->sh_type);

        if (outfd != stdout && !in_database(outfd, sect_name, sect_type)) {
            (*n_items)++;
            fprintf(outfd, "%s,%s\n", sect_name, sect_type);
        }
    }

    malelf_close(&elf_obj);

    return MALELF_SUCCESS;
}

_u8 in_database(FILE* database, char* sect_name, char* sect_type) {
    char line[256], *buf = NULL;
    size_t len;
    
    char *tmp_name = NULL, *tmp_type = NULL;
    
    fseek(database, 0L, SEEK_SET);

    while (!feof(database)) {
        bzero(line, 256);
        if (!fgets(line, 256, database)) {
            break;
        }

        /* fgets returns the new line in buffer... strip this */
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = '\0';

        len = strcspn(line, ",");
        if (len < strlen(line)) {
            line[len] = '\0';
            buf = line + len + 1;
            tmp_name = line;
            tmp_type = buf;

            if (!strcmp(tmp_name, sect_name) &&
                !strcmp(tmp_type, sect_type)) {
                return 1;
            }
        }
    }

    fseek(database, 0L, SEEK_END);

    return 0;
}


