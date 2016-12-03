# Generated automatically from Makefile.in by configure.
CC=gcc
CFLAGS=-g -I/usr/local/ssl/include  -std=c99 -Wall 
LD=-L/usr/local/ssl/lib  -lssl -lcrypto -ldl


all:  simpletun

simpletun: simpletun.o AES.o HMAC.o 
		$(CC) $(CFLAGS) simpletun.o AES.o HMAC.o  -o simpletun $(LD)

simpletun.o: simpletun.c
	$(CC) $(CFLAGS) -c simpletun.c $(LD)

AES.o: AES.c
	$(CC) $(CFLAGS) -c AES.c $(LD)

HMAC.o: HMAC.c
	$(CC) $(CFLAGS) -c HMAC.c $(LD)

clean:	
	rm *.o
