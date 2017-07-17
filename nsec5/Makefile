CFLAGS=-std=gnu11 -Wall -g -O2 -Icrypto
#CFLAGS += -fsanitize=address

openssl_FLAGS=$(shell pkg-config --cflags --libs libcrypto)
nettle_FLAGS=$(shell pkg-config --cflags --libs nettle hogweed) -lgmp
gnutls_FLAGS=$(shell pkg-config --cflags --libs "gnutls >= 3.0") $(nettle_FLAGS) -lgmp

.PHONY: all clean

all: demo_openssl demo_gnutls

clean:
	rm -f demo_openssl demo_gnutls

demo_openssl: demo/main.c demo/openssl.c crypto/openssl_fdh.c
	$(CC) $(CFLAGS) $(openssl_FLAGS) -o $@ $^

demo_gnutls: demo/main.c demo/gnutls.c crypto/gnutls_fdh.c crypto/nettle_fdh.c crypto/nettle_mgf.c
	$(CC) $(CFLAGS) $(gnutls_FLAGS) -o $@ $^
