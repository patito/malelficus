#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>

#include <elf.h>
#include <link.h>

#define SAYR(where, fmt...) fprintf(where, fmt)
#define SAY(fmt...) SAYR(stdout, "[+] " fmt)
#define SAY_ERROR(fmt...) SAYR(stderr, "[-] " fmt)
#define MAX_MSG_ERROR 255

#define MALELF_ERRNO(msg_fmt...) do {\
  malelf_error.code = errno; \
  snprintf(malelf_error.message, MAX_MSG_ERROR, msg_fmt); \
  malelf_error.is_errno = 1;} while(0)

#define malelf_fatal() do {malelf_perror(); SAY_ERROR("Aborting...\n"); exit(malelf_error.code); } while(0)

typedef uint8_t _u8;
typedef int32_t _i32;

typedef enum {
  SUCCESS = 0,
  ERROR = 1  
} malelf_status;

typedef struct {
  ElfW(Ehdr) *elfh;
  ElfW(Phdr) *elfp;
  ElfW(Shdr) *elfs;
} elf_t;

typedef struct {
  char* fname;
  int fd;
  struct stat st_info;
  _u8* mem;
  elf_t elf;
} elf_object;

typedef struct {
  char message[MAX_MSG_ERROR];
  char* func;
  _i32 code;
  _u8 is_errno;
} malelf_err;

static malelf_err malelf_error;

void malelf_perror() {
  if (malelf_error.is_errno) {
    SAY_ERROR("Malelficus:[code %d] %s - OS message: %s\n", malelf_error.code, malelf_error.message, sys_errlist[malelf_error.code]);
  } else {
    SAY_ERROR("ERROR: [%d] %s\n", malelf_error.code, malelf_error.message);
  }  
}

_i32 malelf_openr(elf_object* obj, const char* filename) {
  assert(obj != NULL);
  assert(filename != NULL);
  obj->fname = (char*) filename;
  obj->fd = open(filename, O_RDONLY);

  if (obj->fd == -1) {
    MALELF_ERRNO("Failed to open '%s' for read", filename);
    return malelf_error.code;
  }

  if (fstat(obj->fd, &obj->st_info) == -1) {
    MALELF_ERRNO("Failed to stat '%s'.", filename);
    return malelf_error.code;
  }
  
  obj->mem = mmap(0, obj->st_info.st_size, PROT_READ, MAP_SHARED, obj->fd, 0);
  if (obj->mem == MAP_FAILED) {
    MALELF_ERRNO("Failed to map file to memory.");
    return malelf_error.code;
  }

  obj->elf.elfh = (ElfW(Ehdr)*) obj->mem;

  return SUCCESS;
}

void malelf_close(elf_object* obj) {
  assert(obj != NULL);
  if (obj->fd != -1) {
    close(obj->fd);
  }
}

int
main(int argc, char** argv) {
  elf_object obj;
  if (argc < 3) {
    SAY("usage %s <in> <out>\n", *argv);
    return 1;
  }

  if (malelf_openr(&obj, argv[1]) != SUCCESS) {
    malelf_fatal();    
  }

  SAY("[%s][descriptor:%d]\n", obj.fname, obj.fd);
  SAY("start address: %08x\n", obj.elf.elfh->e_entry);

  malelf_close(&obj);

  return 0;  
}
