CFLAGS_LANGUAGE=-std=c99 -pedantic
CFLAGS_WARNS=-Wall -Wextra -Werror
CFLAGS_INCLUDES=-I../external-libs/beangine/include \
		-Iinclude

AM_CFLAGS=	-ggdb -fPIC -O2 $(CFLAGS_LANGUAGE) \
		$(CFLAGS_WARNS) \
		$(CFLAGS_INCLUDES)

lib_LTLIBRARIES=libmalelf.la

libmalelf_la_SOURCES =  object.c \
			reverse_elf.c \
			infect.c \
			util.c \
			error.c \
			disas.c \
			shellcode.c \
			dissect.c \
			print_table.c

libmalelf_la_LDFLAGS = -version-info 1:0:0
libmalelf_la_LIBADD=-lBeaEngine_s_d -L../external-libs/beangine/lib/Linux.gnu.Debug/

library_includedir=$(includedir)/malelf
library_include_HEADERS	=	include/malelf/malelf.h \
				include/malelf/object.h \
				include/malelf/disas.h \
				include/malelf/infect.h \
				include/malelf/reverse_elf.h \
				include/malelf/shellcode.h \
				include/malelf/types.h \
				include/malelf/util.h \
				include/malelf/defines.h \
				include/malelf/error.h \
				include/malelf/dissect.h
