# Simple makefile to build the beacon function objects (TODO - simplify)

CC = i686-w64-mingw32-gcc
CC64 = x86_64-w64-mingw32-gcc
.PHONY: all
all: beacon_funcs beacon_funcs_64

beacon_funcs: beacon_funcs.c
	$(CC) -c beacon_funcs.c -o beacon_funcs.x86.o

beacon_funcs_64: beacon_funcs.c
	$(CC64) -c beacon_funcs.c -o beacon_funcs.x64.o

.PHONY: clean
clean:
	rm -rf beacon_funcs.*.o
