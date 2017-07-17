# Verifiable Random Functions (VRF)

This repository contains sample implementation of cryptographic functions specified in [draft-goldbe-vrf-01](https://tools.ietf.org/html/draft-goldbe-vrf-01).

## Implementation Status

| VRF suite             | OpenSSL             | GnuTLS/Nettle       |
| --------------------- | ------------------- | ------------------- |
| EC-VRF-P256-SHA256    | DONE                | TBD                 |
| EC-VRF-ED25519-SHA256 | N/A \*              | TBD                 |
| RSA-FDH-VRF           | DONE (needs update) | DONE (needs update) |

\* OpenSSL supports optimized implementation of the curve, primitives required for VRF are missing.

## Quick Start

```
$ make
$ ./demo_ecvrf_p256
message = 68:65:6c:6c:6f:20:77:6f:72:6c:64:00
proof = 03:36:82:f3:bd:2a:99:38:23:40:aa:05:e1:6c:5d:40:3f:f4:1a:5a:99:fe:70:27:e5:75:42:69:92:c4:36:50:df:18:70:8d:12:63:70:e2:b5:bc:1b:9d:65:3b:09:9c:36:69:ee:be:71:f0:b8:65:e2:03:d4:09:28:6c:9c:f2:a4:b8:4b:11:25:cd:6f:48:3c:d3:99:df:60:0d:0d:f1:1c
valid = true
```

See `nsec5` directory for RSA-FDH-VRF according to older specification.

## Rerefences

- [NSEC5 Project Page](http://www.cs.bu.edu/~goldbe/papers/nsec5.html)
- [Draft on IETF Data Tracker](https://datatracker.ietf.org/doc/draft-goldbe-vrf/)

## License

Apache License 2.0
