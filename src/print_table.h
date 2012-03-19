#ifndef PRINT_TABLE_H
#define PRINT_TABLE_H

typedef struct {
  char name[80];
  int size;
} tb_column;

typedef struct {
  tb_column* col;
  int n_col;
} tb_line;

typedef tb_line tb_header;
typedef tb_line tb_generic_line;

extern void print_table_generic(tb_line*, int, int, int);
extern void print_table_line(tb_line*, int, int);
extern void print_table_header(tb_header*, int, int);
extern void print_table_header_art(int, int);

#endif
