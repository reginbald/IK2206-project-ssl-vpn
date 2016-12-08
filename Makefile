# Generated automatically from Makefile.in by configure.
CC=gcc
CFLAGS=-g -I/usr/local/ssl/include
LD=-L/usr/local/ssl/lib  -lssl -lcrypto -ldl
SRC = $(wildcard *.c)
OBJS = $(SRC:.c=.o)

all:  simpletun

simpletun: $(OBJS)
		$(CC) $(CFLAGS) $(OBJS)  -o simpletun $(LD)

%.o : %.c
	$(CC) $(CFLAGS)  -c $<

clean:	
	rm *.o simpletun
