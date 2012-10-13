/**
 * get out of here immediately!
 * cursed code!
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "malelf/print_table.h"

/**
 * param1 = struct line
 * param2 = size of the line table (sum of columns length)
 * param3 = length of the screen where the table need to be positioned
 *
 * This function dump a structure line or header to screen.
 *
 * TODO: DANGER! THIS CODE IS UGLY AND BADLY WRITTEN!
 *
 * Psychographed by i4k, written by a ghost programmer crazy!
 *
 * This function was coded in early morning of 19 March.
 * There must be hundreds of bugs but I had to write this code very fast
 * because that the format tricks of printf doesn't help me  and now I'm
 * too lazy to improve it! All this does not justify... i know ...but I try ...
 */
void __print_table_generic(tb_line* l, int line_size, int fit_on_screen, int has_header) {
  int def_with_cols = 0, i = 0, j = 0,
    left_screen = 0, right_screen = 0, rem_screen = 0, screen_space = 0;
  int total_column_width = 0;
  int sum_cols = 0;

  assert(line_size <= fit_on_screen);
  if (line_size == 0) {
    line_size = fit_on_screen;
  }

  screen_space = line_size;

  rem_screen = fit_on_screen - line_size;
  screen_space -= l->n_col + 1;
  def_with_cols = screen_space / l->n_col;

  for (i = 0; i < l->n_col; i++) {
    if (l->col[i].size > 0) {
      total_column_width += l->col[i].size;
    } else {
      total_column_width += def_with_cols;
    }
  }

  if (total_column_width > line_size) {
    fprintf(stderr, "total_column_width: %d\n", total_column_width);
    fprintf(stderr, "line_size = %d\n", line_size);
    fprintf(stderr, "total length of columns is bigger that the size of line\n");
    exit(1);
  }

  if (rem_screen > 0) {
    if (rem_screen % 2 == 0) {
      left_screen = right_screen = rem_screen / 2;
    } else {
      left_screen = rem_screen / 2 + 1;
      right_screen = left_screen - 1;
    }
  }

  if (has_header == 1) {
    print_table_header_art(line_size, left_screen);
  }

  for (i = 0; i < left_screen; i++) {
    printf(" ");
  }
  
  for (i = 0; i < l->n_col; i++) {
    tb_column *c = &l->col[i];
    int left = 0, right = 0;
    int diff = 0;

    if (c->size != 0) {
      diff = c->size - strlen(c->name);
      sum_cols += c->size;
    } else {
      diff = def_with_cols - strlen(c->name);
      sum_cols += def_with_cols;
    }
    
    if (diff < 0) {
      c->name[strlen(c->name)+diff] = 0;
      diff = 0;
    }
    
    if (diff > 0) {
      if (diff % 2 == 0) {
        left = right = diff/2;
      } else {
        left = diff/2 + 1;
        right = left - 1;        
      }
    }
    printf("|");

    for (j = 0; j < left; j++) {
      printf(" ");
    }

    printf("%s", c->name);

    for (j = 0; j < right; j++) {
      printf(" ");
    }
  }

  /* padding the last column */
  for (i = 0; i < screen_space - sum_cols; i++) {
    printf(" ");
  }

  printf("|");

  for (i = 0; i < right_screen; i++) {
    printf(" ");
  }

  printf("\n");

  if (has_header == 1) {
    print_table_header_art(line_size, left_screen);
  }
}

void print_table_header(tb_header *h, int header_size, int fit_on_screen) {
  __print_table_generic(h, header_size, fit_on_screen, 1);
}

void print_table_line(tb_line *l, int line_size, int fit_on_screen) {
  __print_table_generic(l, line_size, fit_on_screen, 0);
}

void print_table_header_art(int header_size, int left_screen) {
  int i;
  for (i = 0; i < left_screen; i++) {
    printf(" ");
  }

  for (i = 0; i < header_size; i++) {
    if (i == 0 || i == header_size - 1) {
      printf("+");
    } else {
      printf("-");
    }
  }

  printf("\n");
}


#if 0

/**
 * HOW TO USE THIS SHIT CODE? SEE BELOW!
 */
int main() {
  column c1,c2,c3, c4;
  column* cols;
  header h1;
  line l1;

  strncpy(c1.name, "struct member", 80);
  strncpy(c2.name, "Description", 80);
  strncpy(c3.name, "Value", 80);
  strncpy(c4.name, "Offset", 80);

  c1.size = c3.size = c4.size = 0;
  c2.size = 0;
  h1.n_col = 4;
  cols = malloc(4 * sizeof(column));
  cols[0] = c1;
  cols[1] = c2;
  cols[2] = c3;
  cols[3] = c4;
  
  h1.col = cols;
  
  print_table_header(&h1, 0, 80);

  l1.n_col = 4;
  l1.col = cols;

  print_table_line(&l1, 0, 80);

  free(h1.col);
  

  return 0;
}

#endif
