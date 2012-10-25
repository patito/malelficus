#include <stdio.h>
#include <string.h>
#include <stdint.h>

static unsigned _debug_ = 1;

#define DEBUG(fmt...) if (_debug_) fprintf(stdout, "[!] "fmt)

#define ENV_MAX_VARIABLES 1000
#define VAR_MAX_LENGTH 10
#define STR_MAX 100

typedef uint32_t _u32;
typedef uint16_t _u16;
typedef uint8_t _u8;

typedef int32_t _i32;
typedef int16_t _i16;
typedef int8_t _i8;

#define GET_INTEGER(variable) (variable.val._int.v)
#define GET_STRING(variable) (variable.val._str.v)
#define PRINT_INTEGER(variable) printf("%d\n", GET_INTEGER(variable))
#define PRINT_STR(variable) printf("%s\n", GET_STRING(variable))
#define PRINT_VAR(variable) do { if (variable.type == INT) PRINT_INTEGER(variable); else if (variable.type == STR) PRINT_STR(variable); } while(0)

enum _branch_type {
  IF = 0,
  ASSIGN
};

enum _operator {
  EQUAL,
  NOT_EQUAL,
  MINOR,
  MAJOR
};

enum __type_t {
  STR = 0,
  INT
};

struct _type_t {
  enum __type_t type;
  char name[VAR_MAX_LENGTH];
  union _val_t {
    struct _string_t {
      _u32 len;
      char v[STR_MAX];
    } _str;

    struct _int_t {
      _i32 v;
    } _int;
  } val;
};

struct _env_t {
  unsigned n_vars;
  struct _type_t vars[ENV_MAX_VARIABLES];
};

struct _ast_t {
  enum _branch_type ast_type;
  struct _env_t env;
  union _branch_t {
    struct _if_t {
      int lvalue;
      int rvalue;
      enum _operator op;
    } _if;

    struct _assign_t {
      struct _type_t lvalue;
      struct _type_t rvalue;
    } _assign;

    struct _sum_t {
      int lvalue;
      int rvalur;
    } _sum;

    struct _print_t {
      int value;
    } _print;    
  } branch;
  struct _ast_t *next_ast;
};

void new_var(struct _ast_t *ast,
             struct _type_t *var,
             char* name,
             enum __type_t type,
             void *val) {
  var->type = STR;
  strncpy(var->name, name, STR_MAX);

  DEBUG("variable %s created\n", name);
  switch (type) {
  case STR:
    memcpy(var->val._str.v, val, strlen((char*) val));
    break;

  case INT: {
    int *v = val;
    var->val._int.v = *v;
    break;
  }
  default:
    var->val._int.v = (int) *((int*)val);
    break;
  }

  memcpy(&ast->env.vars[ast->env.n_vars], var, sizeof(struct _type_t));
  ast->env.n_vars++;
}

int get_var(struct _ast_t *ast,
             struct _type_t **var,
             const char* name) {
  unsigned i = 0;

  for (i = 0; i < ENV_MAX_VARIABLES; i++) {
    struct _type_t *t = &ast->env.vars[i];

    if (!strcmp(t->name, name)) {
      printf("found var %s ", t->name);
      PRINT_INTEGER((*t));
      *var = t;
      return 1;
    }
  }

  return 0;
}

void assign(struct _ast_t *ast, const char* name, void* value) {

}

struct _ast_t ast;

void execute_ast() {

}

int main() {
  struct _type_t var1, var2, var3, *var4;
  _i32 i = 10, j = 20;

  ast.env.n_vars = 0;
  new_var(&ast, &var1, "variable1", 1, &i);
  new_var(&ast, &var2, "variable2", 1, &j);
  new_var(&ast, &var3, "str", STR, "hello world");

  PRINT_INTEGER(var1);
  PRINT_INTEGER(var2);
  PRINT_STR(var3);

  if (get_var(&ast, &var4, "variable1")) {
    PRINT_VAR((*var4));
  } else {
    printf("failed to get variable\n");
  }

  assign(&ast, "variable1", 15);

  PRINT_VAR(var1);

  assign(&ast, "variable1", 20);

  PRINT_VAR(var1);
  
  return 0;
}
