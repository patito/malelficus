#ifndef UTIL_H
#define UTIL_H

/**
 * Macros
 */
#define LOG_RAW(out, format...) fprintf(out, format)
#define SAY(format...) LOG_RAW(stdout, format)
#define LOG(format...) LOG_RAW(stdout, "[!] " format)
#define LOG_SUCCESS(format...) LOG_RAW(stdout, "[+] " format)
#define LOG_ERROR(format...) LOG_RAW(stderr, "[-] ERROR: " format); exit(ERROR)
#define LOG_WARN(format...) LOG_RAW(stderr, "[-] WARNING: " format)
#define LOG_OFFSET(desc_format, value) \
  if (quiet_mode) { \
    LOG_RAW(stdout, "0x%x", value); \
  } else LOG_RAW(stdout, desc_format, value)

#define ITOA(dest, src) snprintf(dest, sizeof(dest), "%d", src)
#define HTOA(dest, src) snprintf(dest, sizeof(dest), "0x%08x", src)


#endif
