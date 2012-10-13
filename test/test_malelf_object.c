#include <unistd.h>
#include <CUnit.h>
#include <Automated.h>

#include "malelf/malelf.h"

#define TRUE 1
#define FALSE 0

int init_suite_success(void) {
    
    return 0;
}
int clean_suite_success(void) { return 0; }

void test_malelf_init_object(void) {
    malelf_object obj;

    malelf_init_object(&obj);
  
    CU_ASSERT(NULL == obj.fname);
    CU_ASSERT(-1 == obj.fd);
    CU_ASSERT(NULL == obj.mem);
    CU_ASSERT(NULL == obj.elf.elfh);
    CU_ASSERT(NULL == obj.elf.elfp);
    CU_ASSERT(NULL == obj.elf.elfs);
}

void test_malelf_openr() {
    malelf_object obj;
    char *fname = "test_files/uninfected";

    obj.fname = fname;

    CU_ASSERT(MALELF_SUCCESS == malelf_openr(&obj, obj.fname));
    CU_ASSERT(MALELF_READONLY == obj.is_readonly);
    CU_ASSERT(-1 != obj.fd);
    CU_ASSERT(NULL != obj.mem);
    CU_ASSERT(NULL != obj.elf.elfh);
    CU_ASSERT(NULL != obj.elf.elfp);
    CU_ASSERT(NULL != obj.elf.elfs);
    CU_ASSERT(obj.st_info.st_size > 0);
    CU_ASSERT_STRING_EQUAL(fname, obj.fname);
    CU_ASSERT(MALELF_SUCCESS == malelf_close(&obj));
}

void test_malelf_openw() {
    malelf_object obj;
    char *fname = "test_files/empty";

    obj.fname = fname;

    CU_ASSERT(MALELF_SUCCESS == malelf_openw(&obj, obj.fname));
    CU_ASSERT(MALELF_READWRITE == obj.is_readonly);
    CU_ASSERT(-1 != obj.fd);

    /* malelf_openw truncate the file */
    CU_ASSERT(NULL == obj.mem);
    CU_ASSERT(NULL == obj.elf.elfh);
    CU_ASSERT(NULL == obj.elf.elfp);
    CU_ASSERT(NULL == obj.elf.elfs);
    CU_ASSERT(obj.st_info.st_size == 0);
    CU_ASSERT_STRING_EQUAL(fname, obj.fname);
    CU_ASSERT(MALELF_SUCCESS == malelf_close(&obj));

    if (unlink(fname) == -1) {
        perror("failed to unlink file.\n");
    }
}

void test_malelf_check_elf() {
    malelf_object obj;
    obj.fname = "test_files/uninfected";

    CU_ASSERT(MALELF_SUCCESS == malelf_openr(&obj, obj.fname));
    CU_ASSERT(MALELF_SUCCESS == malelf_check_elf(&obj));

    CU_ASSERT(MALELF_SUCCESS == malelf_close(&obj));
}

int main() {
    CU_pSuite pSuite = NULL;

    /* initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    /* add a suite to the registry */
    pSuite = CU_add_suite("malELFicus Test Suite", init_suite_success, clean_suite_success);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* add the tests to the suite */
    if (
        (NULL == CU_add_test(pSuite, "testing malelf_init_object()", test_malelf_init_object)) ||
        (NULL == CU_add_test(pSuite, "testing malelf_openr", test_malelf_openr)) ||
        (NULL == CU_add_test(pSuite, "testing malelf_openw", test_malelf_openw)) ||
        (NULL == CU_add_test(pSuite, "testing malelf_check_elf", test_malelf_check_elf))
        ) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_set_output_filename("test_malelf_object");
    /* Run all tests using the automated interface */
    CU_automated_run_tests();
    CU_list_tests_to_file();

    /* Clean up registry and return */
    CU_cleanup_registry();
    return CU_get_error();
}
