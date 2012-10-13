#include <CUnit.h>
#include <Automated.h>
#include "malelf/object.h"

#define TRUE 1
#define FALSE 0

int init_suite_success(void) { return 0; }
int init_suite_failure(void) { return -1; }
int clean_suite_success(void) { return 0; }
int clean_suite_failure(void) { return -1; }

void test_success1(void)
{
   CU_ASSERT(TRUE);
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
   if ((NULL == CU_add_test(pSuite, "successful_test_1", test_success1)))
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