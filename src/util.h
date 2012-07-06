#ifndef UTIL_H
#define UTIL_H

#include "defines.h"
#include "types.h"

/**
 * Macros
 */
#define LOG_RAW(out, format...) fprintf(out, format)
#define SAY(format...) LOG_RAW(stdout, format)
#define LOG(format...) LOG_RAW(stdout, "[!] " format)
#define LOG_SUCCESS(format...) LOG_RAW(stdout, "[+] " format)
#define LOG_ERROR(format...) do { LOG_RAW(stderr, "[-] ERROR: " format); exit(ERROR); } while(0) 
#define LOG_WARN(format...) LOG_RAW(stderr, "[-] WARNING: " format)
#define LOG_OFFSET(desc_format, value) \
  if (quiet_mode) { \
    LOG_RAW(stdout, "0x%x", value); \
  } else LOG_RAW(stdout, desc_format, value)

#define ITOA(dest, src) snprintf(dest, sizeof(dest), "%d", src)
#define HTOA(dest, src) snprintf(dest, sizeof(dest), "0x%08x", src)

typedef enum {
  SUCCESS = 0,
  ERROR = 1  
} malelf_status;

extern _u8 saveFile(const char* fname, _u8 *mem, off_t size);

#endif
