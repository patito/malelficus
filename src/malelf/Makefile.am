CFLAGS_LANGUAGE=-std=c99 -pedantic
CFLAGS_WARNS=-Wall -Wextra -Werror
CFLAGS_INCLUDES=-I../external-libs/beangine/include/beaengine -I../libmalelf/include

AM_CFLAGS=	-ggdb -O2 $(M32_CFLAGS) $(CFLAGS_LANGUAGE) \
		$(CFLAGS_WARNS) \
		$(CFLAGS_INCLUDES)

bin_PROGRAMS = malelf

malelf_SOURCES = 	main.c \
			analyse.c \
			database.c

malelf_LDADD = -L../libmalelf -lmalelf
