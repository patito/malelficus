#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "error.h"

void malelf_perror(int code) {
  if (code >= 0 && code < LAST_ERRNO) {
    LOG_ERROR("[%d] %s\n", code, strerror(code));
  } else {
    LOG_ERROR("[%d] Unknow error", code);
  }
}
