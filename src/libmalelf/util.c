#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <malelf/util.h>
#include <malelf/error.h>

extern _u8 malelf_quiet_mode;

int malelf_log(FILE* fd, const char* prefix, const char *format, va_list args) {
  char outbuf[MAX_LOG_BUFFER];
  char n_format[MAX_LOG_BUFFER];
  int i;
  size_t len;

  bzero(outbuf, MAX_LOG_BUFFER);
  bzero(n_format, MAX_LOG_BUFFER);
  strncpy(n_format, prefix, strlen(prefix));
  strncat(n_format, format, MAX_LOG_BUFFER - strlen(n_format));
  
  i = vsprintf(outbuf, n_format, args);

  len = strlen(outbuf);
  if (fwrite(outbuf, sizeof(char), len, fd) == len) {
      va_end(args);
    return i;
  } else {
    return  -1;
  }
}

int malelf_print(FILE* fd, const char* format, ...) {
  va_list args;
  va_start(args, format);
  return malelf_log(fd, "", format, args);
}

int malelf_say(const char *format, ...) {
  va_list args;
  va_start(args, format);
  return malelf_log(stdout, "", format, args);
}

int malelf_error(const char *format, ...) {
  va_list args;
  va_start(args, format);
  return malelf_log(stderr, "[-] ", format, args);
}

int malelf_success(const char* format, ...) {
  va_list args;
  va_start(args, format);
  return malelf_log(stdout, "[+] ", format, args);
}

int malelf_warn(const char* format, ...) {
  va_list args;
  va_start(args, format);
  return malelf_log(stderr, "[!] ", format, args);
}

_u8 saveFile(const char* fname, _u8 *mem, off_t size) {
  int h_fd;

  h_fd = open(fname, O_RDWR|O_FSYNC|O_CREAT, S_IRWXU);

  if (h_fd == -1) {
    LOG_ERROR("Failed to open file to write: %s\n", fname);
  }

  if (write(h_fd, mem, size) != size) {
    LOG_ERROR("Failed to write the entire file...\n");
  }

  close(h_fd);

  return MALELF_SUCCESS;
}

