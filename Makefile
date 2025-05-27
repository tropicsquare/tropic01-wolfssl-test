#Define the compiler if necessry (f.i. for cross-compilation)
#CC = gcc

# Replace with correct path to libtropic! 
LIBTROPIC_DIR = /home/skyworker/Work/libtropic


SRCS = main.c


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
          -lm

ifdef RPI_SPI
SRCS += $(LIBTROPIC_DIR)/hal/port/unix/lt_port_raspberrypi_wiringpi.c
LDFLAGS += -lwiringPi
else
SRCS += $(LIBTROPIC_DIR)/hal/port/unix/lt_port_unix_usb_dongle.c
endif

OBJS = $(SRCS:.c=.o)

all: lt-wolfssl-test


$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

lt-wolfssl-test: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


clean:
	rm -f lt-wolfssl-test $(OBJS)

run: lt-wolfssl-test
	./lt-wolfssl-test

.PHONY: all clean run


