SUBDIRS=malwares host 

TESTS=			malelf_object \
			infection

check_PROGRAMS = 	malelf_object \
			infection

bin_PROGRAMS = 		malelf_object \
			infection

AM_CFLAGS=		-Wall -Werror -ggdb \
			-I../src/external-libs/CUnit/CUnit/Headers \
			-I../src/libmalelf/include

infection_LDADD=	-L../src/external-libs/CUnit/CUnit/Sources/.libs \
			-lcunit \
			-L../src/libmalelf/.libs -lmalelf

malelf_object_LDADD=	-L../src/external-libs/CUnit/CUnit/Sources/.libs \
			-lcunit \
			-L../src/libmalelf/.libs -lmalelf

infection_SOURCES=	test_infection.c

malelf_object_SOURCES = test_malelf_object.c





