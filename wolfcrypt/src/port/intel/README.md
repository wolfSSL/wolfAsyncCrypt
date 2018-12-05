# Intel QuickAssist Adapter Asynchronous Support

The wolfSSL / wolfCrypt libraries support hardware crypto acceleration using the Intel QuickAssist adapter. This software has been tested using QAT 1.6 in user space on Cent OS (Kernel 3.10.0-327.22.2.el7.x86_64) on an Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz. Intel QuickAssist is DH895xCC (BDF=03:00.0, Stepping A0, device 0 is SKU2).

## Overview

Support has been added for wolfCrypt for RSA public/private (CRT/non-CRT), AES CBC/GCM, ECDH/ECDSA, DH, DES3, SHA, SHA224, SHA256, SHA384, SHA512, MD5 and HMAC. RSA padding is done via software. The wolfCrypt tests and benchmarks have asynchronous. The wolfCrypt benchmark tool support multi-threading. The wolfSSL SSL/TLS async support has been extended to include all PKI, Encryption/Decryption and hashing/HMAC. An async hardware simulator has been added to test the asynchronous support without hardware.

The Intel QuickAssist port files are located in `wolfcrypt/src/port/intel/quickassist.c` and `wolfssl/wolfcrypt/port/intel/quickassist.h`. The QuickAssist memory handling for NUMA and normal malloc is in `wolfcrypt/src/port/intel/quickassist_mem.c`.

The asynchronous crypto files are located at `wolfcrypt/src/async.c` and `wolfssl/wolfcrypt/async.h`. These files are not in the public repository. Please contact info@wolfssl.com if interested in our asynchronous support to request an evaluation.


## Building

QuickAssist drivers can be downloaded from Intel here:
https://01.org/intel-quick-assist-technology/downloads

### QAT 1.7

Note: If you have the older driver installed you may need to remove it or unload the module and reboot.

1. Setup `QAT1.7` and `wolfssl` next to each other in the same folder.

2. Build QAT 1.7
	
	Prerequisites: 
	`sudo apt-get install libudev-dev`
	
	
	```
	wget https://01.org/sites/default/files/downloads/intelr-quickassist-technology/qat1.7.l.4.3.0-00033.tar.gz
	mkdir QAT1.7
	mv qat1.7.l.4.3.0-00033.tar.gz QAT1.7
	cd QAT1.7
	tar -xvzf qat1.7.l.4.3.0-00033.tar.gz

	./configure
	make
	sudo make install
	```

	If you are using the QAT hardware hashing, you'll need to disable the params checking, which doesn't support a last partial with 0 length source input. Code runs and works, but parameter checking will fail.
	Use `./configure --disable-param-check && sudo make install`
	
	Build warning fixes:
	
	a. quickassist/lookaside/access_layer/src/common/include/lac_log.h:102
	
	`"%s() - : " log "\n",` -> `(char*)"%s() - : " log "\n",`
	
	b. quickassist/lookaside/access_layer/src/common/include/lac_common.h:1151
	
	Add these above `default:`
	
	```
	case ICP_ADF_RING_SERVICE_9:
		return SAL_RING_TYPE_TRNG;
	case ICP_ADF_RING_SERVICE_10:
	```


3. Change owner permissions for build output directory:
	
	`sudo chown [user]:[user] build`
	
	To manually startup the services you can use:
	
	```
	sudo modprobe usdm_drv
	sudo service qat_service start
	```

4. Build wolfSSL:
	
	```
	cd ../wolfssl
	./configure --with-intelqa=../QAT1.7 --enable-asynccrypt
	make
	```	
	

### QAT 1.6

1. Setup `QAT1.6` and `wolfssl` next to each other in the same folder.
2. Build the QAT 1.6:
  * Run the installer using `sudo ./installer.sh`
  * Choose option 3 to install.
  * After reboot you'll need to make sure and load the qaeMemDrv.ko module. `sudo insmod ./QAT1.6/build/qaeMemDrv.ko`
3. Build wolfSSL:
  * `./configure --enable-asynccrypt --with-intelqa=../QAT1.6 && make`

## Usage

Running wolfCrypt test and benchmark must be done with `sudo` to allow hardware access. By default the QuickAssist code uses the "SSL" process name via `QAT_PROCESS_NAME` in quickassist.h to match up to the hardware configuration.

Note: `sudo make check` will fail since default QAT configuration doesn't allow multiple concurrent processes to use hardware. You can run each of the make check scripts individually with sudo. The hardware configuration can be customized by editing the `QAT1.6/build/dh895xcc_qa_dev0.conf` file to allow multiple processes.

Here are some build options for tuning your use:

1. `QAT_USE_POLLING_CHECK`: Enables polling check to ensure only one poll per crypto instance.
2. `WC_ASYNC_THREAD_BIND`: Enables binding of thread to crypto hardware instance.
3. `WOLFSSL_DEBUG_MEMORY_PRINT`: Enables verbose malloc/free printing. This option is used along with `WOLFSSL_DEBUG_MEMORY` and `WOLFSSL_TRACK_MEMORY`.
4. `WC_ASYNC_THRESH_NONE`: Disables the default thresholds for determining if software AES/DES3 is used. Otherwise you can define `WC_ASYNC_THRESH_AES_CBC`, `WC_ASYNC_THRESH_AES_GCM` and `WC_ASYNC_THRESH_DES3_CBC` with your own values. The defaults are AES CBC: 1024, AES GCM 128, DES3 1024. If the symmetric operation is over this size it will use QAT hardware. Otherwise software.
5. `WC_ASYNC_NO_CRYPT`: When defined with disable QAT use for AES/DES3.
6. `WC_ASYNC_NO_HASH`: When defined disables the QAT for hashing (MD5,SHA,SHA256,SHA512).
7. `WC_ASYNC_NO_RNG`: When defined disables the QAT DRBG (default for QAT v1.7)
8. `WC_NO_ASYNC_THREADING`: Disables the thread affinity code for optionally linking a thread to a specific QAT instance. To use this feature you must also define `WC_ASYNC_THREAD_BIND`.

The QuickAssist v1.6 driver uses its own memory management system in `quickassist_mem.c`. This can be tuned using the following defines:

1. `USE_QAE_STATIC_MEM`: Uses a global pool for the list of allocations. This improves performance, but consumes extra up front memory. The pre-allocation size can be tuned using `QAE_USER_MEM_MAX_COUNT`.
2. `USE_QAE_THREAD_LS` : Uses thread-local-storage and removes the mutex. Can improve performance in multi-threaded environment, but does use extra memory.

For QuickAssist v1.7 the newer usdm memory driver is used directly.

### Recommended wolfSSL Build Options

`./configure --with-intelqa=../QAT1.7 --enable-asynccrypt --enable-aesni --enable-intelasm --enable-intelrand CFLAGS="-DWC_ASYNC_NO_HASH"`

* `--enable-asynccrypt`: Enables asynchronous cryptography mode.
* `--with-intelqa=../QAT1.7`: Enables the Intel QuickAssist mode.
* `--enable-aesni`: Enables the Intel AES-NI assembly speedups.
* `--enable-intelasm`: Enables the Intel ASM (AVX/AVX2) speedups.
* `--enable-intelrand`: Enables the Intel RDRAND support for RNG source.
* `WC_ASYNC_NO_HASH`: Disable the QAT hashing and use Intel AVX accelerated software hashing. Overhead for using QAT hashing is not yet well tuned.

### wolfCrypt Test with QAT
```
sudo ./wolfcrypt/test/testwolfcrypt
IntelQA: Instances 6
RSA      test passed!
```

### wolfCrypt Benchmark with QAT (multi-threaded)

Multiple concurrent threads will be started based on the number of CPU's available. If you want to exclude the software benchmarks use `./configure CFLAGS="-DNO_SW_BENCH"`.

```
IntelQA: Instances 18
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
CPUs: 8
RSA     2048 public    HW  34100 ops took 1.000 sec, avg 0.029 ms, 34095.635 ops/sec
RSA     2048 public    HW  34000 ops took 1.001 sec, avg 0.029 ms, 33978.799 ops/sec
RSA     2048 public    HW  33800 ops took 1.001 sec, avg 0.030 ms, 33778.208 ops/sec
RSA     2048 public    HW  33800 ops took 1.001 sec, avg 0.030 ms, 33761.813 ops/sec
RSA     2048 public    HW  34100 ops took 1.001 sec, avg 0.029 ms, 34058.652 ops/sec
RSA     2048 public    HW  34200 ops took 1.002 sec, avg 0.029 ms, 34145.163 ops/sec
RSA     2048 public    HW  33900 ops took 1.002 sec, avg 0.030 ms, 33815.701 ops/sec
RSA     2048 public    HW  33600 ops took 1.003 sec, avg 0.030 ms, 33508.223 ops/sec
RSA   2048 public    HW 271142.193 ops/sec
RSA     2048 private   HW   5500 ops took 1.001 sec, avg 0.182 ms, 5493.633 ops/sec
RSA     2048 private   HW   5300 ops took 1.002 sec, avg 0.189 ms, 5287.025 ops/sec
RSA     2048 private   HW   5300 ops took 1.006 sec, avg 0.190 ms, 5270.490 ops/sec
RSA     2048 private   HW   5300 ops took 1.006 sec, avg 0.190 ms, 5266.076 ops/sec
RSA     2048 private   HW   5300 ops took 1.007 sec, avg 0.190 ms, 5265.406 ops/sec
RSA     2048 private   HW   5300 ops took 1.007 sec, avg 0.190 ms, 5265.139 ops/sec
RSA     2048 private   HW   5300 ops took 1.007 sec, avg 0.190 ms, 5261.763 ops/sec
RSA     2048 private   HW   5400 ops took 1.009 sec, avg 0.187 ms, 5350.953 ops/sec
RSA   2048 private   HW 42460.485 ops/sec
DH      2048 key gen   HW   8670 ops took 1.000 sec, avg 0.115 ms, 8668.768 ops/sec
DH      2048 key gen   HW   8400 ops took 1.001 sec, avg 0.119 ms, 8394.258 ops/sec
DH      2048 key gen   HW   8475 ops took 1.001 sec, avg 0.118 ms, 8466.804 ops/sec
DH      2048 key gen   HW   8460 ops took 1.001 sec, avg 0.118 ms, 8451.766 ops/sec
DH      2048 key gen   HW   8745 ops took 1.001 sec, avg 0.114 ms, 8735.942 ops/sec
DH      2048 key gen   HW   8535 ops took 1.001 sec, avg 0.117 ms, 8524.336 ops/sec
DH      2048 key gen   HW   8475 ops took 1.001 sec, avg 0.118 ms, 8466.490 ops/sec
DH      2048 key gen   HW   8655 ops took 1.001 sec, avg 0.116 ms, 8643.460 ops/sec
DH    2048 key gen   HW 68351.825 ops/sec
DH      2048 agree     HW  12200 ops took 1.001 sec, avg 0.082 ms, 12188.896 ops/sec
DH      2048 agree     HW  11400 ops took 1.002 sec, avg 0.088 ms, 11378.585 ops/sec
DH      2048 agree     HW  11800 ops took 1.004 sec, avg 0.085 ms, 11754.415 ops/sec
DH      2048 agree     HW  11700 ops took 1.005 sec, avg 0.086 ms, 11642.312 ops/sec
DH      2048 agree     HW  11700 ops took 1.005 sec, avg 0.086 ms, 11641.663 ops/sec
DH      2048 agree     HW  11300 ops took 1.005 sec, avg 0.089 ms, 11240.415 ops/sec
DH      2048 agree     HW  10800 ops took 1.005 sec, avg 0.093 ms, 10741.023 ops/sec
DH      2048 agree     HW  11000 ops took 1.006 sec, avg 0.091 ms, 10939.581 ops/sec
DH    2048 agree     HW 91526.889 ops/sec
ECDHE    256 agree     HW   7400 ops took 1.001 sec, avg 0.135 ms, 7391.175 ops/sec
ECDHE    256 agree     HW   7300 ops took 1.006 sec, avg 0.138 ms, 7259.239 ops/sec
ECDHE    256 agree     HW   6600 ops took 1.002 sec, avg 0.152 ms, 6588.083 ops/sec
ECDHE    256 agree     HW   6900 ops took 1.010 sec, avg 0.146 ms, 6834.884 ops/sec
ECDHE    256 agree     HW   7600 ops took 1.013 sec, avg 0.133 ms, 7502.380 ops/sec
ECDHE    256 agree     HW   6800 ops took 1.008 sec, avg 0.148 ms, 6744.901 ops/sec
ECDHE    256 agree     HW   7300 ops took 1.001 sec, avg 0.137 ms, 7292.518 ops/sec
ECDHE    256 agree     HW   7200 ops took 1.001 sec, avg 0.139 ms, 7192.655 ops/sec
ECDHE  256 agree     HW 56805.836 ops/sec
ECDSA    256 sign      HW   8000 ops took 1.001 sec, avg 0.125 ms, 7989.972 ops/sec
ECDSA    256 sign      HW   7300 ops took 1.002 sec, avg 0.137 ms, 7286.542 ops/sec
ECDSA    256 sign      HW   8100 ops took 1.003 sec, avg 0.124 ms, 8073.172 ops/sec
ECDSA    256 sign      HW   7400 ops took 1.005 sec, avg 0.136 ms, 7364.518 ops/sec
ECDSA    256 sign      HW   7300 ops took 1.005 sec, avg 0.138 ms, 7264.787 ops/sec
ECDSA    256 sign      HW   7400 ops took 1.005 sec, avg 0.136 ms, 7361.367 ops/sec
ECDSA    256 sign      HW   7400 ops took 1.006 sec, avg 0.136 ms, 7352.569 ops/sec
ECDSA    256 sign      HW   7400 ops took 1.007 sec, avg 0.136 ms, 7345.884 ops/sec
ECDSA  256 sign      HW 60038.811 ops/sec
ECDSA    256 verify    HW   4300 ops took 1.003 sec, avg 0.233 ms, 4286.972 ops/sec
ECDSA    256 verify    HW   4300 ops took 1.010 sec, avg 0.235 ms, 4259.041 ops/sec
ECDSA    256 verify    HW   4100 ops took 1.011 sec, avg 0.246 ms, 4056.916 ops/sec
ECDSA    256 verify    HW   4100 ops took 1.011 sec, avg 0.247 ms, 4056.642 ops/sec
ECDSA    256 verify    HW   4100 ops took 1.011 sec, avg 0.247 ms, 4056.574 ops/sec
ECDSA    256 verify    HW   4100 ops took 1.012 sec, avg 0.247 ms, 4051.936 ops/sec
ECDSA    256 verify    HW   4100 ops took 1.014 sec, avg 0.247 ms, 4044.678 ops/sec
ECDSA    256 verify    HW   4100 ops took 1.015 sec, avg 0.247 ms, 4041.085 ops/sec
ECDSA  256 verify    HW 32853.845 ops/sec
IntelQA: Stop
```

### wolfCrypt Benchmark with QAT (single-threaded)

To use the benchmark tool against hardware in single threaded mode build the library with `./configure CFLAGS="-DWC_NO_ASYNC_THREADING -DNO_SW_BENCH"`.

```
sudo ./wolfcrypt/benchmark/benchmark -rsa -dh -ecc
IntelQA: Instances 18
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RSA     2048 public    HW 161000 ops took 1.000 sec, avg 0.006 ms, 160989.829 ops/sec
RSA     2048 private   HW  18600 ops took 1.002 sec, avg 0.054 ms, 18566.416 ops/sec
DH      2048 key gen   HW  48945 ops took 1.000 sec, avg 0.020 ms, 48931.782 ops/sec
DH      2048 agree     HW  43300 ops took 1.001 sec, avg 0.023 ms, 43248.876 ops/sec
ECDHE    256 agree     HW  26400 ops took 1.001 sec, avg 0.038 ms, 26382.639 ops/sec
ECDSA    256 sign      HW  23900 ops took 1.004 sec, avg 0.042 ms, 23810.849 ops/sec
ECDSA    256 verify    HW  13800 ops took 1.000 sec, avg 0.072 ms, 13799.878 ops/sec
IntelQA: Stop
```

### wolfSSL Asynchronous Test Mode

Enable asynccrypt alone to use async simulator.
`./configure --enable-asynccrypt`


## Debugging

To enable debug messages:
`./configure --enable-asynccrypt --with-intelqa=../QAT1.6 --enable-debug --disable-shared CFLAGS="-DQAT_DEBUG" && make`


## Support

For questions or issues email us at support@wolfssl.com.
