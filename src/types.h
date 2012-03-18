#ifndef TYPES_H
#define TYPES_H

typedef uint8_t _u8;
typedef uint16_t _u16;
typedef uint32_t _u32;
typedef int8_t _i8;
typedef int16_t _i16;
typedef int32_t _i32;

typedef struct {
  char* name;
  _u16 val;
  char* desc;
} object_ftype;

#endif
