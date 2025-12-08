# wolfSSL / wolfCrypt Asynchronous Support

## Repository Deprecated

**This repository has been deprecated.**

With wolfSSL's move to GPLv3, all asynchronous cryptography support files have been upstreamed directly into the main wolfSSL repository at [https://github.com/wolfssl/wolfssl](https://github.com/wolfssl/wolfssl).

**The last version with separate asynchronous bundles was v5.8.4.** All releases after v5.8.4 will include all asynchronous cryptography files directly in the main wolfSSL distribution.

## Files Moved

All files from this repository have been moved to the main wolfSSL repository. Below is a list of the files and their new locations:

### Documentation
- `README.md` → [README-async.md](https://github.com/wolfssl/wolfssl/blob/master/README-async.md)

### Core Async Files
- `wolfcrypt/src/async.c` → [wolfcrypt/src/async.c](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/async.c)
- `wolfssl/wolfcrypt/async.h` → [wolfssl/wolfcrypt/async.h](https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/async.h)

### Intel QuickAssist Port
- `wolfcrypt/src/port/intel/quickassist.c` → [wolfcrypt/src/port/intel/quickassist.c](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/intel/quickassist.c)
- `wolfssl/wolfcrypt/port/intel/quickassist.h` → [wolfssl/wolfcrypt/port/intel/quickassist.h](https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/port/intel/quickassist.h)
- `wolfcrypt/src/port/intel/quickassist_mem.c` → [wolfcrypt/src/port/intel/quickassist_mem.c](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/intel/quickassist_mem.c)
- `wolfssl/wolfcrypt/port/intel/quickassist_mem.h` → [wolfssl/wolfcrypt/port/intel/quickassist_mem.h](https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/port/intel/quickassist_mem.h)
- `wolfcrypt/src/port/intel/build.sh` → [wolfcrypt/src/port/intel/build.sh](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/intel/build.sh)
- `wolfcrypt/src/port/intel/README.md` → [wolfcrypt/src/port/intel/README.md](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/intel/README.md)

### Cavium Nitrox Port
- `wolfcrypt/src/port/cavium/cavium_nitrox.c` → [wolfcrypt/src/port/cavium/cavium_nitrox.c](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/cavium/cavium_nitrox.c)
- `wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h` → [wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h](https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h)
- `wolfcrypt/src/port/cavium/README.md` → [wolfcrypt/src/port/cavium/README.md](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/cavium/README.md)
- `wolfcrypt/src/port/cavium/README_Octeon.md` → [wolfcrypt/src/port/cavium/README_Octeon.md](https://github.com/wolfssl/wolfssl/blob/master/wolfcrypt/src/port/cavium/README_Octeon.md)

For the latest asynchronous cryptography support, please use the main wolfSSL repository at [https://github.com/wolfssl/wolfssl](https://github.com/wolfssl/wolfssl).

## Support

For questions email wolfSSL support at support@wolfssl.com
