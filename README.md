# NSEC5 Crypto

This repository contains **sample implementation** of cryptographic functions required for NSEC5.

The implementation covers following libraries:

- OpenSSL
- Nettle
- GnuTLS (3.0 or newer)

## Quick Start

Fetch the source code, compile demo programs, generate an RSA key, and run the demo:

```
$ git clone https://gitlab.labs.nic.cz/knot/nsec5-crypto.git
$ cd nsec5-crypto
$ make
$ openssl genrsa 2048 > key.pem
$ ./demo_openssl sha1 key.pem testinput
```

## Demo

To compile included demo programs (`demo_openssl` and `demo_gnutls`), execute `make` in the root of the repository.
If all libraries and *pkg-config* are available, everything should go smoothly.

```
$ make
cc -std=gnu99 -Wall -g -O2 -Icrypto -lcrypto  -o demo_openssl demo/main.c demo/openssl.c crypto/openssl_fdh.c
cc -std=gnu99 -Wall -g -O2 -Icrypto -lgnutls -lnettle -lhogweed  -lgmp -o demo_gnutls demo/main.c demo/gnutls.c crypto/gnutls_fdh.c crypto/nettle_fdh.c crypto/nettle_mgf.c
```

To compile individual demo programs, run `make demo_<name>` as usual:

```
$ make demo_openssl
cc -std=gnu99 -Wall -g -O2 -Icrypto -lcrypto  -o demo_openssl demo/main.c demo/openssl.c crypto/openssl_fdh.c
```

To override compilation and linking parameters for dependend libraries (also required when *pkg-config* is not available), add `<name>_FLAGS` parameter:

```
$ make demo_openssl openssl_FLAGS="-I/usr/local/include -L/usr/local/lib64 -lcrypto"
cc -std=gnu99 -Wall -g -O2 -Icrypto -I/usr/local/include -L/usr/local/lib64 -lcrypto -o demo_openssl demo/main.c demo/openssl.c crypto/openssl_fdh.c
```

The demo program takes a name of a hash function, a private RSA key in PEM format, and input from the command line. The input is then signed and verified:

```
$ ./demo_gnutls sha1 key_1024.pem teststring
## GnuTLS
# input
74 65 73 74 73 74 72 69 6e 67 
# signature
51 7b dd a8 b3 ee c2 f5 a7 bf fc f5 d5 67 96 d1
7d a0 b2 a7 a9 db 49 cb 2c 4b c7 50 b6 ab 79 dd
57 49 d3 39 64 c4 9b a4 0f b1 8e 4c 46 33 0b 86
c7 c0 10 0b a6 29 fc 3c 08 b4 18 5b 7d bf 7b e7
f7 31 78 1b a5 4d d1 10 4f 08 47 95 4f 83 7e 7c
2f ab 14 98 05 3a 40 a0 f4 d4 b7 18 f0 49 56 52
f8 d1 df c4 e0 47 8e 95 2b 0f 4d 0c 4c bb 83 91
8b 0a 33 1e 6c 77 45 f7 c5 25 da 01 09 8d 43 c4
# verification
succeeded
```

To generate a new RSA key, the utilities supplied with OpenSSL or GnuTLS can be used:

```
(openssl)$ openssl genrsa 2048 > key.pem
(gnutls)$ certtool --generate-privkey --rsa --bits 2048 > key.pem
```

## Rerefences

TBD

## License

TBD
