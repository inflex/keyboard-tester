default: keyboard-tester

CC=gcc
LIBS=-lm $(shell sdl2-config --static-libs)
CFLAGS=-Wall -O2 $(shell sdl2-config --cflags)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm *.o keyboard-tester

keyboard-tester: keyboard-tester.c 
	$(CC) $(CFLAGS) keyboard-tester.c -o keyboard-tester $(LIBS)

