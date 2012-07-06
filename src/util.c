#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util.h"

_u8 saveFile(const char* fname, _u8 *mem, off_t size) {
  int h_fd;

  h_fd = open(fname, O_RDWR|O_FSYNC|O_CREAT, S_IRWXU);

  if (h_fd == -1) {
    LOG_ERROR("Failed to open file to write: %s\n", fname);
  }

  if (write(h_fd, mem, size) != size) {
    LOG_ERROR("Failed to write the entire file...\n");
  }

  return SUCCESS;
}
