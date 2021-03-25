CC = i686-w64-mingw32-gcc
CC64 = x86_64-w64-mingw32-gcc

.PHONY: all
all: demo_bof demo_bof_64

demo_bof: demo_bof.c
	$(CC) -c demo_bof.c -o demo_bof.x86.o
	
demo_bof_64: demo_bof.c
	$(CC64) -c demo_bof.c -o demo_bof.x64.o

.PHONY: clean
clean:
	rm -rf demo_bof.*.o
