/*
  Malelficus
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

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <link.h> /* ElfW(type) and others */

#include <malelf/defines.h>
#include <malelf/util.h>
#include <malelf/error.h>
#include <malelf/types.h>
#include <malelf/object.h>
#include <malelf/dissect.h>
#include <malelf/reverse_elf.h>
#include <malelf/infect.h>
#include <malelf/disas.h>
#include <malelf/shellcode.h>

#include "database.h"
#include "analyse.h"

#ifdef __STDC__
extern int fileno(FILE*);
#endif

#define DEFAULT_SECTION_DATABASE "~/.malelficus/data/sections.csv"

/**
 * function prototypes
 */
void help(),
    help_entry_point(),
    help_dissect(),
    help_shellcode(),
    help_reverse_elf(),
    help_infect(),
    help_copy(),
    help_disas(),
    help_analyse(),
    help_database();

_u8 saveFile(const char*, _u8*, off_t);
_u8 entry_point(int argc, char** argv);
_u8 dissect(int argc, char** argv);
_u8 shellcode(int argc, char** argv);
_u8 pht(int argc, char** argv);

/**
 * Global variables
 */
_u8 malelf_verbose_mode = 0;
extern _u8 malelf_quiet_mode;

char* program_name;

/**
 * Software design
 *
 * The main goal of malELFicus is help in the process of virus development,
 * for this purpose we need split the software in tasks. Each task have
 * your own options and parameters so that I've decided to propagate the
 * arguments of user to function callback that handle each task.
 */

/**
 * Handle entry point
 *
 * %s entry_point [-qhvg] [-u address] [-i <input-file>] [-o <output-file>]
 *
 * -q quiet mode
 * -h entry point help
 * -v verbose mode
 * -g get binary entry point
 * -u <offset> update entry point offset
 * -i <file> input binary file
 * -o <file> output binary file
 */
_u8 entry_point(int argc, char** argv) {
    _u8 action = 0;
    _u32 offset_update = 0x00;
    int opt;
    malelf_object input, output;

#define ACTION_GET 0x01
#define ACTION_UPDATE 0x02

    while((opt = getopt(argc, argv, "qhvgu:i:o:")) != -1) {
        switch(opt) {
        case 'h':
            help_entry_point();
            break;
        case 'q':
            malelf_quiet_mode = 0x01;
            break;
        case 'v':
            malelf_verbose_mode = 0x01;
            break;
        case 'g':
            action = ACTION_GET;
            break;
        case 'u':
            action = ACTION_UPDATE;
            sscanf(optarg, "%x", &offset_update);
            break;
        case 'i':
            input.fname = optarg;
            break;
        case 'o':
            output.fname = optarg;
            break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_entry_point();
        }
    }

    if (input.fname == NULL) {
        LOG_WARN("No ELF binary file set to get entry point!\n");
        help_entry_point();
    }

    malelf_openr(&input, input.fname);
  
    if (malelf_check_elf(&input) == MALELF_ERROR) {
        LOG_ERROR("invalid ELF!!! aborting...\n");
    }

    if (action != ACTION_GET && action != ACTION_UPDATE) {
        LOG_ERROR("Command 'entry_point' need the option -g or -u\n");
    }

    if (action == ACTION_GET) {
        LOG_OFFSET("Entry point: 0x%x\n", input.elf.elfh->e_entry);
    } else if (action == ACTION_UPDATE) {
        if (output.fname != NULL) {
            copy_malelf_object_raw(&output, &input);
            output.elf.elfh->e_entry = offset_update;
            saveFile(output.fname, output.mem, output.st_info.st_size);
            free(output.mem);
        } else {
            LOG_ERROR("In command 'entry_point' the option -u needs the option -o <file>\n");
        }
    }

    if (input.mem != NULL) {
        munmap(input.mem, input.st_info.st_size);
    }
  
    return MALELF_SUCCESS;
}

_u8 copy(int argc, char** argv) {
    malelf_object input, output;
    char *input_filename = NULL, *output_filename = NULL;
    int opt, copy_opt = 0;
    malelf_add_section_t add_section;
    int ret = MALELF_SUCCESS;
#define ADD_SECTION 0x01

    input.fname = NULL;
    output.fname = NULL;

    while((opt = getopt(argc, argv, "han:d:i:o:")) != -1) {
        switch(opt) {
        case 'h':
            help_copy();
            break;
        case 'a':
            copy_opt |= ADD_SECTION;
            break;
        case 'n':
            add_section.name = optarg;
            break;
        case 'd':
            add_section.data_fname = optarg;
            break;
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_copy();
        }
    }

    if (input_filename == NULL) {
        LOG_WARN("No ELF binary file set to copy. Use -i\n");
        help_copy();
    }

    if (output_filename == NULL) {
        LOG_WARN("No ELF binary output file. Use -o\n");
        help_copy();
    }

    if ((ret = malelf_openr(&input, input_filename)) != MALELF_SUCCESS) {
        malelf_perror(ret);
    }

    if ((ret = malelf_openw(&output, output_filename)) != MALELF_SUCCESS) {
        malelf_perror(ret);
    }

    if ((copy_opt & ADD_SECTION) == ADD_SECTION) {
        malelf_add_section(&input, &output, add_section);
    }

    malelf_close(&input);
    malelf_close(&output);
  
    return 0;
}

_u8 shellcode(int argc, char** argv) {
    int opt, shellcode_size = 0;
    unsigned long int original_entry_point = 0, magic_bytes = 0;
    char* input_filename = NULL;
    char* output_filename = NULL;
    char* output_type = NULL;
    FILE *fd_i, *fd_o;
    struct stat st_info;
    _i32 error = 0;
  
    while((opt = getopt(argc, argv, "hi:o:t:z:s:")) != -1) {
        switch(opt) {
        case 'h':
            help_shellcode();
            break;
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 't':
            output_type = optarg;
            break;
        case 'z':
            original_entry_point = (unsigned long int) strtol(optarg, NULL, 16);
            break;
        case 's':
            shellcode_size = atoi(optarg);
            break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_shellcode();
        }
    }

    if (input_filename == NULL) {
        LOG_WARN("No ELF binary file create shellcode!\n");
        help_shellcode();
    }

    fd_i = fopen(input_filename, "r");
    if (!fd_i) {
        perror("Permission denied to open input binary.\n");
        return -1;
    }

    if (stat(input_filename, &st_info) == -1) {
        perror("failed to stat file.\n");
        fclose(fd_i);
        return -1;
    }

    if (st_info.st_size == 0) {
        LOG_ERROR("Empty file '%s'.\n", input_filename);
        fclose(fd_i);
        exit(-1);
    }

    if (shellcode_size == 0 || shellcode_size > st_info.st_size) {
        shellcode_size = st_info.st_size;
    }

    if (!output_filename) {
        fd_o = stdout;
    } else {
        fd_o = fopen(output_filename, "w");
        if (!fd_o) {
            perror("Permission denied to open output file.\n");
            fclose(fd_i);
            return -1;
        }
    }

    if (!output_type)
        output_type = "c";

    if (!strcmp("c", output_type)) {
        error = shellcode_create_c(fd_o, shellcode_size, fd_i, original_entry_point);
    } else if (!strcmp("malelficus", output_type)) {
        if (fd_o == stdout) {
            LOG_ERROR("Option -t malelficus *require* a output file. Use -o <file>\n");
            goto shellcode_exit;            
        }
        error = shellcode_create_malelficus(fd_o, shellcode_size, fd_i, original_entry_point, magic_bytes);
    } else {
        LOG_ERROR("Unsupported output type: %s\n", output_type);
        goto shellcode_exit;
    }

    if (error != MALELF_SUCCESS)
        malelf_perror(error);

 shellcode_exit:
    fclose(fd_i);
    if (fd_o != stdout && fd_o != stderr) {
        fclose(fd_o);
    }
    
    return MALELF_SUCCESS;
}

_u8 dissect(int argc, char** argv) {
    malelf_object input;
    elf_t *elf = NULL;
    _u16 option = 0;
    char* input_filename = NULL;
    int opt;
    int error = MALELF_SUCCESS;

#define DISPLAY_EHT 0x01
#define DISPLAY_PHT 0x02
#define DISPLAY_SHT 0x04
#define DISPLAY_STRTAB 0x08

    input.fname = NULL;

#define ACTION_DISSECT 0x01
#define ACTION_PHT 0x02

    while((opt = getopt(argc, argv, "hepsSi:")) != -1) {
        switch(opt) {
        case 'h':
            help_dissect();
            break;
        case 'e':
            option |= DISPLAY_EHT;
            break;
        case 'p':
            option |= DISPLAY_PHT;
            break;
        case 's':
            option |= DISPLAY_SHT;
            break;
        case 'S':
            option |= DISPLAY_STRTAB;
            break;
        case 'i':
            input_filename = optarg;
            break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_dissect();
        }
    }

    if (input_filename == NULL) {
        LOG_WARN("No ELF binary file set to dissect!\n");
        help_dissect();
    }

    if (option == 0) {
        option = DISPLAY_EHT | DISPLAY_SHT | DISPLAY_PHT | DISPLAY_STRTAB;
    }

    if ((error = malelf_openr(&input, input_filename)) != MALELF_SUCCESS) {
        malelf_perror(error);
        malelf_fatal(error);
    }

    elf = &input.elf;

    if ((option & DISPLAY_EHT) == DISPLAY_EHT) {
        pretty_print_elf_header(elf->elfh);
        SAY("\n");
    }

    if ((option & DISPLAY_PHT) == DISPLAY_PHT) {
        pretty_print_pht(elf->elfh, elf->elfp);
        SAY("\n");
    }

    if ((option & DISPLAY_SHT) == DISPLAY_SHT) {
        pretty_print_sht(&input, elf->elfh, elf->elfs);
        SAY("\n");
    }

    if ((option & DISPLAY_STRTAB) == DISPLAY_STRTAB) {
        pretty_print_strtab(&input, elf->elfh, elf->elfs);
        SAY("\n");
    }
  
    return MALELF_SUCCESS;
}

void reverse_elf(int argc, char** argv) {
    malelf_object input;
    int opt_getopt = 0, opt = 0;
    FILE *fd_output = NULL;
    char* input_filename = NULL, *output_filename = NULL;
#define REVERSE_ELF 1
#define MOUNT_ELF 2

    while((opt_getopt = getopt(argc, argv, "hmri:o:")) != -1) {
        switch(opt_getopt) {
        case 'h':
            help_reverse_elf();
            break;
        case 'r':
            if (opt != 0) {
                LOG_ERROR("-m OR -r is granted, not both.\n");
                help_reverse_elf();
                exit(1);
            }
            opt = REVERSE_ELF;
            break;
        case 'm':
            if (opt != 0) {
                LOG_ERROR("-m OR -r is granted, not both.\n");
                help_reverse_elf();
                exit(1);
            }
            opt = MOUNT_ELF;
            break;
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_dissect();
        }
    }

    if (input_filename == NULL) {
        LOG_ERROR("-i input filename not specified.\n");
        help_reverse_elf();
        exit(1);
    }
  
    if (output_filename == NULL) {
        fd_output = stdout;
    } else {
        fd_output = fopen(output_filename, "w");
        if (!fd_output) {
            perror("Error when open file for write...");
            exit(1);
        }
    }

    if (opt == REVERSE_ELF) {
        input.fname = input_filename;
        malelf_openr(&input, input.fname);
        reverse_elf2c(&input, fd_output);
    } else {
        LOG_ERROR("-m or -r is required.\n");
        help_reverse_elf();
        exit(1);
    }

    if (output_filename && fd_output) {
        fclose(fd_output);
    }
  
    if (input.mem != NULL) {
        munmap(input.mem, input.st_info.st_size);
    }
}

void infect(int argc, char** argv) {
    int opt;
    _u8 technique = 0, _auto = 0;
    _i32 error;
    _u32 offset_entry_point = 0;
    unsigned long int magic_bytes = 0;

    typedef enum {
        SILVIO_PADDING = 0
    } technique_t;
  
    malelf_object input, output, parasite;

    input.fname = NULL;
    output.fname = NULL;
    parasite.fname = NULL;

    while((opt = getopt(argc, argv, "hi:o:t:p:m:f:a:b")) != -1) {
        switch(opt) {
        case 'h':
            help_infect();
            break;
        case 'i':
            input.fname = optarg;
            break;
        case 'o':
            output.fname = optarg;
            break;
        case 'm':
            technique = atoi(optarg);
            break;
        case 'b':
            magic_bytes = (unsigned long int) strtol(optarg, NULL, 16);
            break;            
        case 'p':
            parasite.fname = optarg;
            break;
        case 'f':
            offset_entry_point = atoi(optarg);
            break;
        case 'a':
            _auto = 1;
            break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help_infect();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_infect();
        }
    }

    if (input.fname == NULL) {
        help_infect();
        exit(1);
    }

    if (output.fname == NULL) {
        help_infect();
        exit(1);
    }

    if (parasite.fname == NULL) {
        help_infect();
        exit(1);
    }

    if (offset_entry_point == 0 && _auto == 0) {
        LOG_ERROR("offset entry point is required, or use -a to malelficus tries to discover the offset.\n");
        help_infect();
        exit(1);
    }

    if ((error = malelf_openr(&input, input.fname)) != MALELF_SUCCESS) {
        malelf_perror(error);
        LOG_ERROR("Failed to open file '%s'.\n", input.fname);
        exit(-1);
    }

    input.is_readonly = 1;

    if ((error = malelf_openr(&parasite,
                              parasite.fname)) != MALELF_SUCCESS) {
        malelf_perror(error);
        LOG_ERROR("Failed to open parasite file '%s'\n", parasite.fname);
        exit(-1);
    }

    switch (technique) {
    case SILVIO_PADDING:
        error = malelf_infect_silvio_padding(&input,
                                            &output,
                                            &parasite,
                                            offset_entry_point,
                                            magic_bytes);
        break;
    }

    malelf_close(&input);
    malelf_close(&output);
}

void disas(int argc, char** argv) {
    int opt;
    malelf_object input;
    char *out_fname = NULL, *section = NULL;
    FILE *outfd;
    _i32 error;

    input.fname = NULL;

    while((opt = getopt(argc, argv, "hi:o:s:")) != -1) {
        switch(opt) {
        case 'h':
            help_disas();
            break;
        case 'i':
            input.fname = optarg;
            break;
        case 'o':
            out_fname = optarg;
            break;
        case 's':
          section = optarg;
          break;
        case ':':
            LOG_WARN("malelficus: Error - Option `%c' needs a value\n\n", optopt);
            help_infect();
            break;
        case '?':
            LOG_WARN("malelficus: Error - No such option: `%c'\n\n", optopt);
            help_disas();
        }
    }

    if (input.fname == NULL) {
        help_disas();
        exit(1);
    }

    if (out_fname == NULL) {
        outfd = stdout;
    } else {
        outfd = fopen(out_fname, "w");
        if (!outfd) {
            perror("Error when open file for write...");
            exit(1);
        }
    }

    input.is_readonly = 1;
    if (malelf_openr(&input, input.fname) == MALELF_SUCCESS) {
      if (section) {
        error = malelf_disas_section(&input, section, outfd);
      } else {        
        error = malelf_disas(&input, outfd);
      }
    } else {
        LOG_ERROR("Failed to open input file...\n");
        exit(-1);
    }

    if (error != MALELF_SUCCESS) {
      malelf_perror(error);
      exit(-1);
    }
}

void database(int argc, char** argv) {
    int c;
    _u8 is_create = 0, is_update = 0, is_section = 0;
    _i32 error = 0;
    char *scan_input = NULL, *output_database = NULL;
    FILE* outfd;
    _u32 n_items = 0;
    optind = 0;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"create", 0, 0, 'c'},
            {"update", 0, 0, 'u'},
            {"output", 1, 0, 'o'},
            {"scan-input", 1, 0, 'f'},
            {"section", 0, 0, 's'},
            {"quiet", 0, 0, 'q'},
            {"help", 0, 0, 'h'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hcuo:f:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            help_database();
            break;
        case 'q':
            malelf_quiet_mode = 1;
            break;
            
        case 'c':
            is_create = 1;
            break;

        case 'u':
            is_update = 1;
            break;

        case 'f':
            scan_input = optarg;
            break;
        case 'o':
            output_database = optarg;
            break;

        case 's':
            is_section = 1;
            break;
            
        case '?':
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if ((is_create && is_update) || (!is_create && !is_update)) {
        LOG_ERROR("--create OR --update ...\n");
        help_database();
        exit(-1);
    }

    if (!is_section) {
        LOG_ERROR("Please choice a type of database...\n");
        help_database();
        exit(-1);
    }

    if (!scan_input) {
        LOG_ERROR("--scan-input is required ...\n");
        help_database();
        exit(-1);
    }

    if (!output_database) {
        outfd = stdout;
    } else {
        outfd = fopen(output_database, "a+");
        if (!outfd) {
            malelf_perror(errno);
            exit(-1);
        }
    }

    if (is_section) {
        if (is_create) {
            error = create_section_database(scan_input, outfd, &n_items);
            if (error != MALELF_SUCCESS) {
                malelf_perror(error);
            } else {
                LOG_SUCCESS("database '%s' created successfully\n", output_database);
                LOG_SUCCESS("Found %d entries of sections.\n", n_items);
            }
        } else if (is_update) {
            error = update_section_database(scan_input, outfd, &n_items);
            if (error != MALELF_SUCCESS) {
                malelf_perror(error);
            } else {
                LOG_SUCCESS("database '%s' updated successfully.\n", output_database);
                LOG_SUCCESS("Found %d new section names.\n", n_items);
            }
        }
    }

    if (output_database) {
        fclose(outfd);
    }
}

void analyse(int argc, char** argv) {
    int c;
    unsigned malelf_opt = 0;
    malelf_object input;
    struct stat st_info;
    char *out_fname = NULL,
        *sect_name = NULL,
        *segm_name = NULL,
        *section_db = NULL,
        *segment_db = NULL;
    FILE *outfd = NULL, *section_db_fp = NULL, *segment_db_fp = NULL;
    _i32 error = 0;

#define ENTRY_POINT 0x01
#define SUSP_SECT (ENTRY_POINT << 1)
#define SUSP_SEGM (ENTRY_POINT << 2)
#define SUSP_INSTR_SECT (ENTRY_POINT << 3)

#define HAS_ENTRY_POINT(val) ((val & ENTRY_POINT) == ENTRY_POINT)
#define HAS_SUSP_SECT(val) ((val & SUSP_SECT) == SUSP_SECT)
#define HAS_SUSP_SEGM(val) ((val & SUSP_SEGM) == SUSP_SEGM)
#define HAS_INSTR_SECT(val) ((val & SUSP_INSTR_SECT) == SUSP_INSTR_SECT)

    input.fname = NULL;

    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"entry-point", 0, 0, 'e'},
            {"suspect-sections", 0, 0, 'S'},
            {"suspect-segments", 0, 0, 'J'},
            {"section", 1, 0, 's'},
            {"segment", 1, 0, 'j'},
            {"help", 0, 0, 'h'},
            {"output", 1, 0, 'o'},
            {"file", 1, 0, 'i'},
            {"section-db", 1, 0, 'z'},
            {"segment-db", 1, 0, 'Z'},
            {"verbose", 0, 0, 'v'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hveSJs:j:o:i:z:Z:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            help_analyse();
            break;
        case 'v':
            malelf_verbose_mode = 1;
            break;
        case 'e':
            malelf_opt |= ENTRY_POINT;
            break;
            
        case 'S':
            malelf_opt |= SUSP_SECT;
            break;

        case 'J':
            malelf_opt |= SUSP_SEGM;
            break;

        case 's':
            sect_name = optarg;
            break;

        case 'j':
            segm_name = optarg;
            break;
        case 'o':
            out_fname = optarg;
            break;

        case 'i':
            input.fname = optarg;
            break;

        case 'z':
            section_db = optarg;
            break;

        case 'Z':
            segment_db = optarg;

        case '?':
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (input.fname == NULL) {
        LOG_ERROR("No input file selected...\n");
        help_analyse();
        exit(1);
    }

    if (out_fname == NULL) {
        LOG_VERBOSE_SUCCESS("Using stdout for log output.\n");
        outfd = stdout;
    } else {
        outfd = fopen(out_fname, "w");
        if (!outfd) {
            perror("Error when open file for write...");
            exit(1);
        }
    }

    input.is_readonly = 1;
  
    if ((error = malelf_openr(&input, input.fname)) != MALELF_SUCCESS) {
        malelf_perror(error);
        LOG_ERROR("Failed to open input file...\n");
        exit(-1);
    }

    if (malelf_check_elf(&input) != MALELF_SUCCESS) {
        LOG_ERROR("%s only analyse ELF binaries...\n", program_name);
        exit(-1);
    }

    if (sect_name != NULL) {
        LOG_SUCCESS("Analysing section: %s\n", sect_name);
    }

    if (segm_name != NULL) {
        LOG_SUCCESS("Analysing segment: %s\n", segm_name);
    }

    if (HAS_ENTRY_POINT(malelf_opt)) {
        LOG_SUCCESS("entry point: %08x\n", input.elf.elfh->e_entry);
    }

    if (!malelf_opt) {
        malelf_opt |= ENTRY_POINT | SUSP_SECT | SUSP_SEGM | SUSP_INSTR_SECT;
    }

    if (HAS_SUSP_SECT(malelf_opt)) {
        if (section_db == NULL) {
            section_db = DEFAULT_SECTION_DATABASE;
            if (stat(section_db, &st_info) == -1) {
                LOG_ERROR("No section database supplied... use --section-db=your-section-database.csv\n");
                goto analyse_exit;
            }
        }

        section_db_fp = fopen(section_db, "r");
        if (!section_db_fp) {
            LOG_ERROR("Failed to open section database '%s'\n", section_db);
            goto analyse_exit;
        }
        
        error = analyse_suspect_section(&input, sect_name, section_db_fp);
        if (error != MALELF_SUCCESS) {
            malelf_perror(error);
            goto analyse_exit;
        }
    }

    if (!HAS_SUSP_SECT(malelf_opt) == 5) {
        if (segment_db == NULL) {
            segment_db = DEFAULT_SECTION_DATABASE;
            if (stat(segment_db, &st_info) == -1) {
                LOG_ERROR("No section database supplied... use --section-db=your-section-database.csv\n");
                goto analyse_exit;
            }
        }

        segment_db_fp = fopen(segment_db, "r");
        if (!segment_db_fp) {
            LOG_ERROR("Failed to open section database '%s'\n", segment_db);
            goto analyse_exit;
        }
        
        error = analyse_suspect_section(&input, sect_name, segment_db_fp);
        if (error != MALELF_SUCCESS) {
            malelf_perror(error);
            goto analyse_exit;
        }
    }

 analyse_exit:
    if (out_fname)
        fclose(outfd);
    if (section_db_fp)
        fclose(section_db_fp);

    malelf_close(&input);
}

int
main(int argc, char **argv) {
    
    program_name = *argv;
    
    if(argc == 1) {
        LOG_WARN("This program needs arguments....\n\n");
        help();
    }

    if (!strcmp("-h", argv[1])) {
        help();
    } else if (!strcmp("analyse", argv[1])) {
        analyse(argc, argv);
    } else if (!strcmp("database", argv[1])) {
        database(argc, argv);
    }  else if (!strcmp("dissect", argv[1])) {
        dissect(argc, argv);
    } else if (!strcmp("entry_point", argv[1])) {
        entry_point(argc, argv);
    } else if (!strcmp("reverse_elf", argv[1])) {
        reverse_elf(argc, argv);
    } else if (!strcmp("infect", argv[1])) {
        infect(argc, argv);
    } else if (!strcmp("shellcode", argv[1])) {
        shellcode(argc, argv);
    } else if (!strcmp("copy", argv[1])) {
        copy(argc, argv);
    } else if(!strcmp("disas", argv[1])) {
        disas(argc, argv);
    } else help();

    return 0;
}

void help() {
    int i;
    const char* banner[] = 
#include "malelficus_banner.h"
        ;

    for (i = 0; i < (int) (sizeof(banner)/sizeof(*banner)); i++)
        printf("%s\n", banner[i]);
  
    SAY("PRESS ENTER TO CONTINUE\n");
    getc(stdin);
    printf("%s <command> <options>\n\n", program_name);

    SAY(" Commands:\n");
    SAY(" \tdissect\n");
    SAY(" \treverse_elf\n");
    SAY(" \tdisas\n");
    SAY(" \tentry_point\n");
    SAY(" \tinfect\n");
    SAY(" \tshellcode\n");
    SAY(" \tcopy\n");
    SAY(" \tdatabase\n");
    SAY(" \tanalyse\n");
  
    SAY("\n");
    SAY("Use:\n \t%s command -h\n to get help about the command.\n"); 

    printf(" -h\tprint this help and exit\n");

    exit(MALELF_SUCCESS);
}

void help_entry_point() {
    SAY("Entry point command\n");
    SAY("%s entry_point [-qhvg] [-u address] [-i <input-file>] [-o <output-file>]\n", program_name);
    SAY(" -q\tquiet mode\n");
    SAY(" -h\tentry point help\n");
    SAY(" -v\tverbose mode\n");
    SAY(" -g\tget binary entry point\n");
    SAY(" -u <offset>\tupdate entry point\n");
    SAY(" -i <file>\tinput binary file\n");
    SAY(" -o <file>\toutput binary file\n");

    exit(MALELF_SUCCESS);
}

void help_dissect() {
    SAY("Dissect command\n");
    SAY("%s dissect [-hvepsS] -i <input file>\n", program_name);
    SAY("\tThis command display information about the ELF binary\n\n");
    SAY(" -h\tdissect help\n");
    SAY(" -i <file>\t Input binary file\n");
    SAY(" -e\tDisplay ELF Header Table\n");
    SAY(" -p\tDisplay Program Header Table\n");
    SAY(" -s\tDisplay Section Header Table\n");
    SAY(" -S\tDisplay Symbol Table\n");
    exit(MALELF_SUCCESS);
}

void help_shellcode() {
    SAY("Shellcode creator\n");
    SAY("%s shellcode [-h] -i <input-shellcode> -o <output> -t <output-type>\n", program_name);
    SAY("\tThis command create the virus shellcode in the proper\n\tformat for use with the ");
    SAY("infect command.\n\n");
    SAY(" -h\tthis help\n");
    SAY(" -i <file>\tInput binary (created by nasm or gas)\n");
    SAY(" -z <original-entry-point> (optional)\n");
    SAY(" -s <shellcode size> (optional)\n");
    SAY(" -t <output-type>\n");
    SAY(" \t\tPossible output types:\n");
    SAY(" \t\t\t- c (default)\n");
    SAY("\n");
    exit(MALELF_SUCCESS);
}

void help_reverse_elf() {
    SAY("Reverse ELF binary\n");
    SAY("%s reverse_elf [-h] -i <input file> [,-o <output-file>]\n", program_name);
    SAY("\tThis command reverse the ELF binary image in the C structs representation.\n");
    SAY("\tIt will provide the chance of manual edit the binary image.\n");
    SAY(" -h\treverse_elf help\n");
    SAY(" -i <file>\tInput binary/source file\n");
    SAY(" -o <file>\tOutput binary/C file\n");
    SAY(" -r Reverse the ELF binary into your C-structures.\n");
    SAY(" -m Mount the C file representarion of the binary into binary\n");
    exit(MALELF_SUCCESS);
}

void help_infect() {
    SAY("Infect ELF binary\n");
    SAY("%s infect [-h] -m <algo> -i <input-binary> [,-o <output-infected-binary>]\n", program_name);
    SAY("\tThis command tries to infect a binary using.\n");
    SAY("\tthe method passed in -m\n");
    SAY(" -h\tinfect help\n");
    SAY(" -m\tInfect methods:\n");
    SAY(" \t\t0 - Silvio Cesare technique (text padding append)\n");
    SAY(" \t\t1 - Text segment prepend (Ryan O'Neill <ryan@bitlackeys.com>)\n");
    SAY(" -i <binary>\tInput binary file\n");
    SAY(" -o <output-binary>\tOutput infected file\n");
    SAY(" -p <malware>\tMalware FLAT binary (eg.: nasm -f bin)\n");
    SAY(" -f <offset-to-return>\tOffset in malware to overwrite with the\n\t\t\ttrue entry_point\n");
    exit(MALELF_SUCCESS);
  
}

void help_copy() {
    SAY("Copy ELF binary\n");
    SAY("%s copy [-h] -i <input-binary> -o <output-binary>]\n", program_name);
    SAY("\tCopy binary ELF.\n");
    SAY("\tthe method passed in -m\n");
    SAY(" -h\tinfect help\n");
    SAY(" -i <binary>\tInput binary file\n");
    SAY(" -o <output-binary>\tOutput file\n");
    exit(MALELF_SUCCESS);
}

void help_disas() {
    SAY("Disassembly ELF binary\n");
    SAY("%s disas [-h] -i <input-binary> [-o <output-asm>]\n", program_name);
    SAY("\tDisassembly binary ELF in NASM compatible format.\n");
    SAY(" -h\tdisas help\n");
    SAY(" -i <binary>\tInput binary file\n");
    SAY(" -o <output-asm>\tOutput file, default is stdout\n");
    exit(MALELF_SUCCESS);
}

void help_analyse() {

}

void help_database() {
    SAY("Database manager\n");
    SAY("%s database [-csu] -f <scan_dir -o <database-output-csv>\n\n", program_name);
    SAY("\t Help in maintanaince of the database of know symbols, sections, segments, etc...\n");
    SAY(" -h/--help\tdatabase help\n");
    SAY(" -c/--create\tCreate a new database file (use in among of --section or --segment, etc).\n");
    SAY(" -u/--update\tUpdate a existing database file.\n");
    SAY(" -f/--scan-input <file-or-directory>\tFile or directory to scanning.\n");
    SAY(" -o/--output <file>\tFile to write the database (default = stdout)\n");
    SAY(" -q/--quiet\tsilent mode (dont print messages).\n");
    SAY("\n\tUsage:\t%s --create --section --scan-file=/usr/bin --output=sections.csv\n");
    SAY("\n\tOR\n\t\t%s -u -s -f /usr/bin -o sections.csv\n", program_name, program_name);
    exit(MALELF_SUCCESS);
}
