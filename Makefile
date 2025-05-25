#CC = gcc
LIBTROPIC_DIR = /home/skyworker/git/libtropic
CFLAGS = -Wall -Wextra -O2 \
         -DWOLFSSL_TROPIC01 \
         -DWOLF_CRYPTO_CB \
         -I$(LIBTROPIC_DIR)/include \
         -I/usr/local/include

LDFLAGS = -L/usr/local/lib \
          -L$(LIBTROPIC_DIR)/build \
		  -L$(LIBTROPIC_DIR)/build/trezor_crypto \
          -lwolfssl \
          -ltropic \
		  -ltrezor_crypto \
          -lwiringPi \
          -lm

all: main

rng_test: main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f main*.o

run: main
	./main

.PHONY: all clean run

