
CFLAGS = -Wall -O3
LDFLAGS = $(CFLAGS) -lstdc++ -lX11 -lcrypto

CC = gcc

.cpp.o:
	$(CC) $(CFLAGS) -c $<

all: passkey

passkey:  passkey.o
	$(CC) -o passkey passkey.o $(LDFLAGS)

clean:
	-rm -f passkey *.o *.a *~ core
