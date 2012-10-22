# Malelficus test files
NASM = nasm
NASM_INCLUDE = ../../samples/inc/

all: clean uninfected malware1 malware2
	@echo "done"

uninfected: uninfected.o
	$(CC) $(CFLAGS) $(LDFLAGS) uninfected.o -o $@

uninfected.o:
	$(CC) -c $(CFLAGS) uninfected.c

malware1: malware1.o
	@echo  -n ""

malware1.o:
	$(NASM) -f bin -o $@ malware1.asm

malware2: malware2.o
	@echo  -n ""

malware2.o:
	$(NASM) -f bin -o $@ malware2.asm

clean:
	rm -f uninfected *.o *.hex

distclean: clean
	@echo "done"

check:
	@echo "done"

install:
	@echo "done"