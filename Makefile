# Generated automatically from Makefile.in by configure.
CC=gcc
CFLAGS=-g -I/usr/local/ssl/include
LD=-L/usr/local/ssl/lib  -lssl -lcrypto -ldl
SRC = $(wildcard *.c)
OBJS = $(SRC:.c=.o)

all:  simpletun

simpletun: $(OBJS)
		$(CC) $(CFLAGS) $(OBJS)  -o simpletun $(LD)

HMAC.o: HMAC.c
	$(CC) $(CFLAGS) -std=c99 -c HMAC.c $(LD)

%.o : %.c
	$(CC) $(CFLAGS)  -c $<

clean:	
	rm *.o simpletun
