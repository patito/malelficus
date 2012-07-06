#include "infect.h"
#include "util.h"
#include "malelf_object.h"

void malelf_infect(malelf_object* input, malelf_object* output) {
  malelf_openr(output, input->fname);

  saveFile(output->fname, output->mem, input->st_info.st_size);
}
