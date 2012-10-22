#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <CUnit.h>
#include <Automated.h>

#include <malelf/error.h>
#include <malelf/object.h>
#include <malelf/shellcode.h>
#include <malelf/infect.h>

#define TRUE 1
#define FALSE 0
#define PAGE_SIZE 4096

int init_suite_success(void) { return 0; }
int init_suite_failure(void) { return -1; }
int clean_suite_success(void) { return 0; }
int clean_suite_failure(void) { return -1; }

void test_malelf_infect_silvio_padding(void)
{
    char* uninfected_path = "test_files/uninfected";
    char* infected_path = "test_files/infected_text_padding";
    char* malware_path = "test_files/malware1.o";
    char* malware_path_gen = "test_files/malware1_gen.o";
    FILE* mal_fd_out, *mal_fd_in;
    unsigned long int magic_bytes = 0;
    struct stat mal_stat_info;
    
    malelf_object input, output, malware;
    _i32 error;

    input.fname = uninfected_path;
    input.is_readonly = 1;
    output.fname = infected_path;

    mal_fd_in = fopen(malware_path, "r");
    CU_ASSERT(mal_fd_in != NULL);

    mal_fd_out = fopen(malware_path_gen, "w");
    CU_ASSERT(mal_fd_out != NULL);
    
    if (mal_fd_out == NULL) {
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
