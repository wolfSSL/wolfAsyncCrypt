# Cavium Nitrox V Support

## Directory Structure:
`/`
    `/CNN55XX-SDK`
    `/wolfssl`

## Cavium Driver

Tested against `CNN55XX-Driver-Linux-KVM-XEN-PF-SDK-1.4.14.tar`

### Installation

```
cd CN55XX-SDK
make clean
make
cd bin
sudo perl ./init_nitrox.pl 
```


## Building wolfSSL

```
./configure --with-cavium-v=../CNN55XX-SDK --enable-asynccrypt --enable-aesni --enable-intelasm
make
```

### Fixes to Nitrox Driver for includes into wolfSSL

1. Modify `include/vf_defs.h:120` -> `vf_config_mode_str()` function to:

```
static inline const char *vf_config_mode_str(vf_config_type_t vf_mode)
{
	const char *vf_mode_str;
```

2. Add `case PF:` to `include/vf_defs.h:82` above `default:` in `vf_config_mode_to_num_vfs()`.

3. In `/include/linux/sysdep.h:46` rename `__BYTED_ORDER` to `__BYTE_ORDER`.


## Usage

Note: Must run applications with sudo to access device.

```
sudo ./wolfcrypt/benchmark/benchmark
sudo ./wolfcrypt/test/testwolfcrypt
```

## Issues

If the CNN55XX driver is not extracted on the Linux box it can cause issues with the symbolic links in the microcode folder. Fix was to resolve the symbolic links in `./microcode`.

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

