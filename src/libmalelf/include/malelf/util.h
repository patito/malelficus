#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdarg.h>
#include "defines.h"
#include "types.h"

#define MAX_LOG_BUFFER 1024

/**
 * Macros
 */
#define LOG_RAW malelf_say
#define SAY if(!malelf_quiet_mode) malelf_say
#define LOG LOG_RAW
#define LOG_SUCCESS if (!malelf_quiet_mode) malelf_success
#define LOG_ERROR if (!malelf_quiet_mode) malelf_error
#define LOG_WARN malelf_warn
#define LOG_OFFSET(desc_format, value)          \
  if (malelf_quiet_mode) {                             \
    LOG_RAW("0x%x", value);                     \
  } else LOG_RAW(desc_format, value)

#define ITOA(dest, src) sprintf(dest, "%d", src)
#define HTOA(dest, src) sprintf(dest, "0x%08x", src)

#define MALELF_UNUSED(var) (void*)var

extern _u8 saveFile(const char* fname, _u8 *mem, off_t size);
extern int malelf_log(FILE *fd, const char* prefix, const char* format, va_list args);
extern int malelf_print(FILE *fd, const char* format, ...);
extern int malelf_say(const char* format, ...);
extern int malelf_success(const char* format, ...);
extern int malelf_error(const char* format, ...);
extern int malelf_warn(const char* format, ...);

#endif
