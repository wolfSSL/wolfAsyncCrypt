# Cavium Nitrox V Support

## Directory Structure:
`/`
    `/CNN55XX-SDK`
    `/wolfssl`

## Building Cavium Driver

Tested using `CNN55XX-Driver-Linux-KVM-XEN-PF-SDK-1.4.14.tar`

### Installation

```
cd CN55XX-SDK
make clean
make
cd bin
sudo perl ./init_nitrox.pl 
```

#### Issues

1. Fixes to Nitrox Driver for includes into wolfSSL

a. Modify `include/vf_defs.h:120` -> `vf_config_mode_str()` function to:

```
static inline const char *vf_config_mode_str(vf_config_type_t vf_mode)
{
	const char *vf_mode_str;
```

b. Add `case PF:` to `include/vf_defs.h:82` above `default:` in `vf_config_mode_to_num_vfs()`.

c. In `/include/linux/sysdep.h:46` rename `__BYTED_ORDER` to `__BYTE_ORDER`.


2. If the CNN55XX driver is not extracted on the Linux box it can cause issues with the symbolic links in the microcode folder. Fix was to resolve the symbolic links in `./microcode`.

```
NITROX Model: 0x1200 [ CNN55XX PASS 1.0 ]
Invalid microcode
ucode_dload: failed to initialize
```

Resolve Links:
```
cd microcode
rm main_asym.out
ln -s ./build/main_ae.out ./main_asym.out
rm main_ipsec.out 
ln -s ./build/main_ipsec.out ./main_ipsec.out
rm main_ssl.out 
ls -s ./build/main_ssl.out ./main_ssl.out
```


## Building wolfSSL

```
./configure --with-cavium-v=../CNN55XX-SDK --enable-asynccrypt --enable-aesni --enable-intelasm
make
sudo make install
```

### CFLAGS

`CFLAGS+= -DHAVE_CAVIUM -DHAVE_CAVIUM_V -DWOLFSSL_ASYNC_CRYPT -DHAVE_WOLF_EVENT -DHAVE_WOLF_BIGINT`
`CFLAGS+= -I../CNN55XX-SDK/include -lrt -lcrypto`

* `HAVE_CAVIUM`: The Cavium define
* `HAVE_CAVIUM_V`: Nitrox V
* `WOLFSSL_ASYNC_CRYPT`: Enable asynchronous wolfCrypt.
* `HAVE_WOLF_EVENT`: Enable wolf event support (required for async)
* `HAVE_WOLF_BIGINT`: Enable wolf big integer support (required for async)


### LDFLAGS

Include the libnitrox static library:
`LDFLAGS+= ../CNN55XX-SDK/lib/libnitrox.a`


## Usage

Note: Must run applications with sudo to access device.

```
sudo ./wolfcrypt/benchmark/benchmark
sudo ./wolfcrypt/test/testwolfcrypt
```

