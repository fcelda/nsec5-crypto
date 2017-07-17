CFLAGS = -std=c11 -g -O2
#CFLAGS += -fsanitize=address

openssl_CFLAGS=$(shell pkg-config --cflags "libcrypto >= 1.1")
openssl_LIBS=$(shell pkg-config --libs "libcrypto >= 1.1")

BINARIES = demo_ecvrf_p256

.PHONY: all
all: $(BINARIES)

demo_ecvrf_p256: demo_ecvrf_p256.c
	$(CC) $(CFLAGS) $(openssl_CFLAGS) -o $@ $^ $(openssl_LIBS)

.PHONY: clean
clean:
	rm -f *.o
	rm -f $(BINARIES)
