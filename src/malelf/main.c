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

#ifdef __STDC__
extern int fileno(FILE*);
#endif

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
 * ./malelficus entry_point [-qhvg] [-u address] [-i <input-file>] [-o <output-file>]
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
    unsigned long int original_entry_point = 0;
    char* input_filename = NULL;
    char* output_filename = NULL;
    char* output_type = NULL;
    FILE *fd_i, *fd_o;
    struct stat st_info;
  
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
        return -1;
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
            return -1;
        }
    }

    if (!output_type || !strcmp("malelficus", output_type)) {
        shellcode_create(fd_o, shellcode_size, fd_i, original_entry_point);
    } else {
        fclose(fd_i);
        if (fd_o != stdout && fd_o != stderr) {
            fclose(fd_o);
        }
    
        LOG_ERROR("Output type not supperted.\n");
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

    typedef enum {
        SILVIO_PADDING = 0
    } technique_t;
  
    malelf_object input, output, parasite;

    input.fname = NULL;
    output.fname = NULL;
    parasite.fname = NULL;

    while((opt = getopt(argc, argv, "hi:o:t:p:m:f:a")) != -1) {
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

    if ((error = malelf_openr(&parasite, parasite.fname)) != MALELF_SUCCESS) {
        malelf_perror(error);
        LOG_ERROR("Failed to open parasite file '%s'\n", parasite.fname);
        exit(-1);
    }

    switch (technique) {
    case SILVIO_PADDING:
        error = malelf_infect_silvio_padding(&input, &output, &parasite, offset_entry_point);
        break;
    }

    malelf_close(&input);
    malelf_close(&output);
}

void disas(int argc, char** argv) {
    int opt;
    malelf_object input;
    char* out_fname = NULL;
    FILE* outfd;

    input.fname = NULL;

    while((opt = getopt(argc, argv, "hi:o:")) != -1) {
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
        malelf_disas(&input, outfd);
    } else {
        LOG_ERROR("Failed to open input file...\n");
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
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "cuo:f:",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
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
    int opt;
    malelf_object input;
    char* out_fname = NULL;
    FILE* outfd;

    input.fname = NULL;

    while((opt = getopt(argc, argv, "hi:o:")) != -1) {
        switch(opt) {
        case 'h':
            help_analyse();
            break;
        case 'i':
            input.fname = optarg;
            break;
        case 'o':
            out_fname = optarg;
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
        LOG_ERROR("No input file selected...\n");
        help_analyse();
        exit(1);
    }

    if (out_fname == NULL) {
        LOG_SUCCESS("Using stdout for log output.\n");
        outfd = stdout;
    } else {
        outfd = fopen(out_fname, "w");
        if (!outfd) {
            perror("Error when open file for write...");
            exit(1);
        }
    }

    input.is_readonly = 1;
  
    if (malelf_openr(&input, input.fname) != MALELF_SUCCESS) {
        LOG_ERROR("Failed to open input file...\n");
        exit(-1);
    }
}

int
main(int argc, char **argv) {

    if(argc == 1) {
        LOG_WARN("This program needs arguments....\n\n");
        help(1);
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
    printf("./malelficus <command> <options>\n\n");

    SAY(" Commands:\n");
    SAY(" \tdissect\n");
    SAY(" \treverse_elf\n");
    SAY(" \tdisas\n");
    SAY(" \tentry_point\n");
    SAY(" \tinfect\n");
    SAY(" \tshellcode\n");
    SAY(" \tcopy\n");
  
    SAY("\n");
    SAY("Use:\n \t./malelficus command -h\n to get help about the command.\n"); 

    printf(" -h\tprint this help and exit\n");

    exit(MALELF_SUCCESS);
}

void help_entry_point() {
    SAY("Entry point command\n");
    SAY("./malelficus entry_point [-qhvg] [-u address] [-i <input-file>] [-o <output-file>]\n");
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
    SAY("./malelficus dissect [-hvepsS] -i <input file>\n");
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
    SAY("./malelficus shellcode [-h] -i <input-shellcode> -o <output> -t <output-type>\n");
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
    SAY("./malelficus reverse_elf [-h] -i <input file> [,-o <output-file>]\n");
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
    SAY("./malelficus infect [-h] -m <algo> -i <input-binary> [,-o <output-infected-binary>]\n");
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
    SAY("./malelficus copy [-h] -i <input-binary> -o <output-binary>]\n");
    SAY("\tCopy binary ELF.\n");
    SAY("\tthe method passed in -m\n");
    SAY(" -h\tinfect help\n");
    SAY(" -i <binary>\tInput binary file\n");
    SAY(" -o <output-binary>\tOutput file\n");
    exit(MALELF_SUCCESS);
}

void help_disas() {
    SAY("Disassembly ELF binary\n");
    SAY("./malelficus disas [-h] -i <input-binary> [-o <output-asm>]\n");
    SAY("\tDisassembly binary ELF in NASM compatible format.\n");
    SAY(" -h\tdisas help\n");
    SAY(" -i <binary>\tInput binary file\n");
    SAY(" -o <output-asm>\tOutput file, default is stdout\n");
    exit(MALELF_SUCCESS);
}

void help_analyse() {

}

void help_database() {

}
