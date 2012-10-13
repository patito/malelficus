#include <stdio.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

/* lua interpreter */
lua_State* l;

int main () {
  int dofile;

  /* initialize lua */
  l = lua_open();

  /* load lua libraries */
  luaL_openlibs(l);

  /* run the hello.lua script */
  dofile = luaL_dofile(l, "hello.lua");

  if (dofile == 0) {
    /* call foo */
    lua_getglobal(l,"foo");
    lua_call(l,0,0);
  }
  else {
    printf("Error, unable to run hello.lua\n");
  }

  /* cleanup Lua */
  lua_close(l);

  return 0;
}
