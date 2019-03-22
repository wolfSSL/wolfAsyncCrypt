# Intel QuickAssist Adapter Asynchronous Support

The wolfSSL / wolfCrypt libraries support hardware crypto acceleration using the Intel QuickAssist adapter. This software has been tested using QAT 1.6 in user space on Cent OS (Kernel 3.10.0-327.22.2.el7.x86_64) on an Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz. Intel QuickAssist is DH895xCC (BDF=03:00.0, Stepping A0, device 0 is SKU2).

## Overview

Support has been added for wolfCrypt for RSA public/private (CRT/non-CRT), AES CBC/GCM, ECDH/ECDSA, DH, DES3, SHA, SHA224, SHA256, SHA384, SHA512, MD5 and HMAC. RSA padding is done via software. The wolfCrypt tests and benchmarks have asynchronous support. The wolfCrypt benchmark tool support multi-threading. The wolfSSL SSL/TLS async support has been extended to include all PKI, Encryption/Decryption and hashing/HMAC. An async hardware simulator has been added to test the asynchronous support without hardware.

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
	wget https://01.org/sites/default/files/downloads/qat1.7.l.4.4.0-00023.tar.gz
	mkdir QAT1.7
	mv qat1.7.l.4.4.0-00023.tar.gz QAT1.7
	cd QAT1.7
	tar -xvzf qat1.7.l.4.4.0-00023.tar.gz

	./configure
	make
	sudo make install
	```

	If you are using the QAT hardware hashing, you'll need to disable the params checking, which doesn't support a last partial with 0 length source input. Code runs and works, but parameter checking will fail.
	Use `./configure --disable-param-check && sudo make install`

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
* `QAT_HASH_ENABLE_PARTIAL`: Enables partial hashing support, which allows sending blocks to hardware prior to final. Otherwise all hash updates are cached.

### wolfCrypt Test with QAT
```
sudo ./wolfcrypt/test/testwolfcrypt
IntelQA: Instances 2
...
RSA      test passed!
```

### wolfCrypt Benchmark with QAT 8970 (multi-threaded)

Multiple concurrent threads will be started based on the number of CPU's available. If you want to exclude the software benchmarks use `./configure CFLAGS="-DNO_SW_BENCH"`.

```
Intel QuickAssist DH8950 on i7-4790 CPU @ 3.60GHz:

./configure --enable-sp --enable-sp-asm --enable-aesni --enable-intelasm --enable-intelrand --enable-keygen --enable-sha3 --enable-asynccrypt --with-intelqa=../QAT1.7 CFLAGS="-DWC_ASYNC_THRESH_NONE -DQAT_MAX_PENDING=40 -DWC_ASYNC_BENCH_THREAD_COUNT=2"									

sudo ./wolfcrypt/benchmark/benchmark -rsa_sign -base10
------------------------------------------------------------------------------
wolfSSL version 3.15.8
------------------------------------------------------------------------------
IntelQA: Instances 2
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
CPUs: 2
RNG             SW    94 mB took 1.010 seconds,   93.464 mB/s Cycles per byte =  38.43
RNG             SW    94 mB took 1.010 seconds,   93.461 mB/s Cycles per byte =  38.43
RNG             SW  186.925 mB/s
AES-128-CBC-enc SW   886 mB took 1.001 seconds,  885.070 mB/s Cycles per byte =   4.06
AES-128-CBC-enc SW   886 mB took 1.001 seconds,  884.872 mB/s Cycles per byte =   4.06
AES-128-CBC-enc SW 1769.941 mB/s
AES-128-CBC-dec SW  6344 mB took 1.000 seconds, 6343.130 mB/s Cycles per byte =   0.57
AES-128-CBC-dec SW  6349 mB took 1.001 seconds, 6344.508 mB/s Cycles per byte =   0.57
AES-128-CBC-dec SW 12687.638 mB/s
AES-192-CBC-enc SW   744 mB took 1.005 seconds,  740.798 mB/s Cycles per byte =   4.85
AES-192-CBC-enc SW   744 mB took 1.005 seconds,  740.646 mB/s Cycles per byte =   4.85
AES-192-CBC-enc SW 1481.444 mB/s
AES-192-CBC-dec SW  5290 mB took 1.000 seconds, 5289.415 mB/s Cycles per byte =   0.68
AES-192-CBC-dec SW  5295 mB took 1.001 seconds, 5290.046 mB/s Cycles per byte =   0.68
AES-192-CBC-dec SW 10579.461 mB/s
AES-256-CBC-enc SW   640 mB took 1.004 seconds,  637.188 mB/s Cycles per byte =   5.64
AES-256-CBC-enc SW   640 mB took 1.004 seconds,  637.063 mB/s Cycles per byte =   5.64
AES-256-CBC-enc SW 1274.250 mB/s
AES-256-CBC-dec SW  4535 mB took 1.000 seconds, 4533.917 mB/s Cycles per byte =   0.79
AES-256-CBC-dec SW  4535 mB took 1.001 seconds, 4532.766 mB/s Cycles per byte =   0.79
AES-256-CBC-dec SW 9066.683 mB/s
AES-128-CBC-enc HW  1442 mB took 1.001 seconds, 1441.028 mB/s Cycles per byte =   2.49
AES-128-CBC-enc HW  1447 mB took 1.002 seconds, 1444.103 mB/s Cycles per byte =   2.49
AES-128-CBC-enc HW 2885.131 mB/s
AES-128-CBC-dec HW  1442 mB took 1.001 seconds, 1440.999 mB/s Cycles per byte =   2.49
AES-128-CBC-dec HW  1447 mB took 1.002 seconds, 1444.088 mB/s Cycles per byte =   2.49
AES-128-CBC-dec HW 2885.087 mB/s
AES-192-CBC-enc HW  1442 mB took 1.000 seconds, 1441.401 mB/s Cycles per byte =   2.49
AES-192-CBC-enc HW  1442 mB took 1.001 seconds, 1439.818 mB/s Cycles per byte =   2.49
AES-192-CBC-enc HW 2881.219 mB/s
AES-192-CBC-dec HW  1442 mB took 1.000 seconds, 1441.334 mB/s Cycles per byte =   2.49
AES-192-CBC-dec HW  1447 mB took 1.002 seconds, 1444.251 mB/s Cycles per byte =   2.49
AES-192-CBC-dec HW 2885.584 mB/s
AES-256-CBC-enc HW  1447 mB took 1.001 seconds, 1445.147 mB/s Cycles per byte =   2.49
AES-256-CBC-enc HW  1452 mB took 1.004 seconds, 1447.078 mB/s Cycles per byte =   2.48
AES-256-CBC-enc HW 2892.226 mB/s
AES-256-CBC-dec HW  1442 mB took 1.000 seconds, 1441.375 mB/s Cycles per byte =   2.49
AES-256-CBC-dec HW  1447 mB took 1.002 seconds, 1444.462 mB/s Cycles per byte =   2.49
AES-256-CBC-dec HW 2885.838 mB/s
AES-128-GCM-enc SW  3235 mB took 1.001 seconds, 3231.592 mB/s Cycles per byte =   1.11
AES-128-GCM-enc SW  3235 mB took 1.001 seconds, 3230.502 mB/s Cycles per byte =   1.11
AES-128-GCM-enc SW 6462.095 mB/s
AES-128-GCM-dec SW  3245 mB took 1.000 seconds, 3244.658 mB/s Cycles per byte =   1.11
AES-128-GCM-dec SW  3245 mB took 1.000 seconds, 3244.577 mB/s Cycles per byte =   1.11
AES-128-GCM-dec SW 6489.235 mB/s
AES-192-GCM-enc SW  2946 mB took 1.001 seconds, 2943.599 mB/s Cycles per byte =   1.22
AES-192-GCM-enc SW  2946 mB took 1.001 seconds, 2942.858 mB/s Cycles per byte =   1.22
AES-192-GCM-enc SW 5886.458 mB/s
AES-192-GCM-dec SW  2957 mB took 1.001 seconds, 2953.381 mB/s Cycles per byte =   1.22
AES-192-GCM-dec SW  2957 mB took 1.001 seconds, 2952.897 mB/s Cycles per byte =   1.22
AES-192-GCM-dec SW 5906.279 mB/s
AES-256-GCM-enc SW  2674 mB took 1.001 seconds, 2671.337 mB/s Cycles per byte =   1.34
AES-256-GCM-enc SW  2674 mB took 1.002 seconds, 2669.787 mB/s Cycles per byte =   1.35
AES-256-GCM-enc SW 5341.123 mB/s
AES-256-GCM-dec SW  2669 mB took 1.000 seconds, 2667.679 mB/s Cycles per byte =   1.35
AES-256-GCM-dec SW  2669 mB took 1.001 seconds, 2666.469 mB/s Cycles per byte =   1.35
AES-256-GCM-dec SW 5334.148 mB/s
AES-128-GCM-enc HW  1442 mB took 1.001 seconds, 1440.080 mB/s Cycles per byte =   2.49
AES-128-GCM-enc HW  1442 mB took 1.003 seconds, 1438.006 mB/s Cycles per byte =   2.50
AES-128-GCM-enc HW 2878.085 mB/s
AES-128-GCM-dec HW  1426 mB took 1.000 seconds, 1425.755 mB/s Cycles per byte =   2.52
AES-128-GCM-dec HW  1431 mB took 1.002 seconds, 1428.727 mB/s Cycles per byte =   2.51
AES-128-GCM-dec HW 2854.483 mB/s
AES-192-GCM-enc HW  1442 mB took 1.000 seconds, 1441.746 mB/s Cycles per byte =   2.49
AES-192-GCM-enc HW  1442 mB took 1.001 seconds, 1439.939 mB/s Cycles per byte =   2.49
AES-192-GCM-enc HW 2881.685 mB/s
AES-192-GCM-dec HW  1431 mB took 1.001 seconds, 1429.199 mB/s Cycles per byte =   2.51
AES-192-GCM-dec HW  1431 mB took 1.003 seconds, 1427.428 mB/s Cycles per byte =   2.52
AES-192-GCM-dec HW 2856.627 mB/s
AES-256-GCM-enc HW  1442 mB took 1.002 seconds, 1439.472 mB/s Cycles per byte =   2.50
AES-256-GCM-enc HW  1442 mB took 1.003 seconds, 1437.524 mB/s Cycles per byte =   2.50
AES-256-GCM-enc HW 2876.996 mB/s
AES-256-GCM-dec HW  1426 mB took 1.001 seconds, 1424.274 mB/s Cycles per byte =   2.52
AES-256-GCM-dec HW  1431 mB took 1.003 seconds, 1426.456 mB/s Cycles per byte =   2.52
AES-256-GCM-dec HW 2850.731 mB/s
CHACHA          SW  3507 mB took 1.000 seconds, 3506.239 mB/s Cycles per byte =   1.02
CHACHA          SW  3507 mB took 1.001 seconds, 3502.526 mB/s Cycles per byte =   1.03
CHACHA          SW 7008.765 mB/s
CHA-POLY        SW  2160 mB took 1.002 seconds, 2156.015 mB/s Cycles per byte =   1.67
CHA-POLY        SW  2160 mB took 1.002 seconds, 2154.837 mB/s Cycles per byte =   1.67
CHA-POLY        SW 4310.853 mB/s
3DES            SW    37 mB took 1.083 seconds,   33.876 mB/s Cycles per byte = 106.02
3DES            SW    37 mB took 1.083 seconds,   33.873 mB/s Cycles per byte = 106.04
3DES            SW   67.749 mB/s
3DES            HW   661 mB took 1.003 seconds,  658.478 mB/s Cycles per byte =   5.45
3DES            HW   661 mB took 1.006 seconds,  656.463 mB/s Cycles per byte =   5.47
3DES            HW 1314.941 mB/s
MD5             SW   713 mB took 1.000 seconds,  712.913 mB/s Cycles per byte =   5.04
MD5             SW   713 mB took 1.000 seconds,  712.804 mB/s Cycles per byte =   5.04
MD5             SW 1425.718 mB/s
MD5             HW   530 mB took 1.006 seconds,  526.545 mB/s Cycles per byte =   6.82
MD5             HW   530 mB took 1.006 seconds,  526.414 mB/s Cycles per byte =   6.82
MD5             HW 1052.959 mB/s
POLY1305        SW  5615 mB took 1.000 seconds, 5614.316 mB/s Cycles per byte =   0.64
POLY1305        SW  5615 mB took 1.000 seconds, 5613.031 mB/s Cycles per byte =   0.64
POLY1305        SW 11227.347 mB/s
SHA             SW   587 mB took 1.001 seconds,  586.620 mB/s Cycles per byte =   6.12
SHA             SW   592 mB took 1.008 seconds,  587.841 mB/s Cycles per byte =   6.11
SHA             SW 1174.461 mB/s
SHA             HW   776 mB took 1.001 seconds,  775.345 mB/s Cycles per byte =   4.63
SHA             HW   776 mB took 1.004 seconds,  773.138 mB/s Cycles per byte =   4.65
SHA             HW 1548.483 mB/s
SHA-224         SW   509 mB took 1.005 seconds,  506.222 mB/s Cycles per byte =   7.10
SHA-224         SW   509 mB took 1.005 seconds,  506.164 mB/s Cycles per byte =   7.10
SHA-224         SW 1012.386 mB/s
SHA-224         HW   556 mB took 1.006 seconds,  552.593 mB/s Cycles per byte =   6.50
SHA-224         HW   556 mB took 1.008 seconds,  551.353 mB/s Cycles per byte =   6.51
SHA-224         HW 1103.945 mB/s
SHA-256         SW   509 mB took 1.005 seconds,  506.179 mB/s Cycles per byte =   7.10
SHA-256         SW   509 mB took 1.005 seconds,  506.104 mB/s Cycles per byte =   7.10
SHA-256         SW 1012.283 mB/s
SHA-256         HW   551 mB took 1.002 seconds,  549.657 mB/s Cycles per byte =   6.53
SHA-256         HW   556 mB took 1.009 seconds,  550.857 mB/s Cycles per byte =   6.52
SHA-256         HW 1100.514 mB/s
SHA-384         SW   718 mB took 1.000 seconds,  718.078 mB/s Cycles per byte =   5.00
SHA-384         SW   718 mB took 1.000 seconds,  717.943 mB/s Cycles per byte =   5.00
SHA-384         SW 1436.021 mB/s
SHA-384         HW   472 mB took 1.006 seconds,  469.019 mB/s Cycles per byte =   7.66
SHA-384         HW   472 mB took 1.009 seconds,  467.867 mB/s Cycles per byte =   7.68
SHA-384         HW  936.886 mB/s
SHA-512         SW   708 mB took 1.004 seconds,  704.991 mB/s Cycles per byte =   5.09
SHA-512         SW   708 mB took 1.004 seconds,  704.902 mB/s Cycles per byte =   5.10
SHA-512         SW 1409.893 mB/s
SHA-512         HW   467 mB took 1.005 seconds,  464.138 mB/s Cycles per byte =   7.74
SHA-512         HW   467 mB took 1.010 seconds,  462.034 mB/s Cycles per byte =   7.77
SHA-512         HW  926.172 mB/s
SHA3-224        SW   346 mB took 1.013 seconds,  341.515 mB/s Cycles per byte =  10.52
SHA3-224        SW   346 mB took 1.013 seconds,  341.478 mB/s Cycles per byte =  10.52
SHA3-224        SW  682.993 mB/s
SHA3-224        HW   346 mB took 1.007 seconds,  343.722 mB/s Cycles per byte =  10.45
SHA3-224        HW   346 mB took 1.007 seconds,  343.717 mB/s Cycles per byte =  10.45
SHA3-224        HW  687.440 mB/s
SHA3-256        SW   325 mB took 1.001 seconds,  324.749 mB/s Cycles per byte =  11.06
SHA3-256        SW   325 mB took 1.001 seconds,  324.728 mB/s Cycles per byte =  11.06
SHA3-256        SW  649.477 mB/s
SHA3-256        HW   325 mB took 1.000 seconds,  324.908 mB/s Cycles per byte =  11.05
SHA3-256        HW   325 mB took 1.001 seconds,  324.794 mB/s Cycles per byte =  11.06
SHA3-256        HW  649.703 mB/s
SHA3-384        SW   252 mB took 1.008 seconds,  249.673 mB/s Cycles per byte =  14.39
SHA3-384        SW   252 mB took 1.008 seconds,  249.612 mB/s Cycles per byte =  14.39
SHA3-384        SW  499.285 mB/s
SHA3-384        HW   252 mB took 1.008 seconds,  249.689 mB/s Cycles per byte =  14.38
SHA3-384        HW   252 mB took 1.008 seconds,  249.622 mB/s Cycles per byte =  14.39
SHA3-384        HW  499.311 mB/s
SHA3-512        SW   178 mB took 1.027 seconds,  173.637 mB/s Cycles per byte =  20.69
SHA3-512        SW   178 mB took 1.027 seconds,  173.605 mB/s Cycles per byte =  20.69
SHA3-512        SW  347.242 mB/s
SHA3-512        HW   178 mB took 1.027 seconds,  173.654 mB/s Cycles per byte =  20.68
SHA3-512        HW   178 mB took 1.027 seconds,  173.616 mB/s Cycles per byte =  20.69
SHA3-512        HW  347.270 mB/s
HMAC-MD5        SW   734 mB took 1.004 seconds,  730.820 mB/s Cycles per byte =   4.91
HMAC-MD5        SW   734 mB took 1.004 seconds,  730.723 mB/s Cycles per byte =   4.92
HMAC-MD5        SW 1461.543 mB/s
HMAC-MD5        HW   545 mB took 1.005 seconds,  542.673 mB/s Cycles per byte =   6.62
HMAC-MD5        HW   551 mB took 1.009 seconds,  545.615 mB/s Cycles per byte =   6.58
HMAC-MD5        HW 1088.288 mB/s
HMAC-SHA        SW   587 mB took 1.001 seconds,  586.458 mB/s Cycles per byte =   6.12
HMAC-SHA        SW   592 mB took 1.008 seconds,  587.690 mB/s Cycles per byte =   6.11
HMAC-SHA        SW 1174.148 mB/s
HMAC-SHA        HW   771 mB took 1.000 seconds,  770.390 mB/s Cycles per byte =   4.66
HMAC-SHA        HW   771 mB took 1.003 seconds,  768.156 mB/s Cycles per byte =   4.68
HMAC-SHA        HW 1538.546 mB/s
HMAC-SHA224     SW   509 mB took 1.005 seconds,  506.078 mB/s Cycles per byte =   7.10
HMAC-SHA224     SW   509 mB took 1.005 seconds,  505.987 mB/s Cycles per byte =   7.10
HMAC-SHA224     SW 1012.065 mB/s
HMAC-SHA224     HW   540 mB took 1.006 seconds,  536.766 mB/s Cycles per byte =   6.69
HMAC-SHA224     HW   540 mB took 1.006 seconds,  536.657 mB/s Cycles per byte =   6.69
HMAC-SHA224     HW 1073.423 mB/s
HMAC-SHA256     SW   509 mB took 1.005 seconds,  506.018 mB/s Cycles per byte =   7.10
HMAC-SHA256     SW   509 mB took 1.005 seconds,  505.941 mB/s Cycles per byte =   7.10
HMAC-SHA256     SW 1011.959 mB/s
HMAC-SHA256     HW   556 mB took 1.001 seconds,  555.394 mB/s Cycles per byte =   6.47
HMAC-SHA256     HW   556 mB took 1.006 seconds,  552.374 mB/s Cycles per byte =   6.50
HMAC-SHA256     HW 1107.768 mB/s
HMAC-SHA384     SW   724 mB took 1.002 seconds,  722.207 mB/s Cycles per byte =   4.97
HMAC-SHA384     SW   724 mB took 1.002 seconds,  722.067 mB/s Cycles per byte =   4.97
HMAC-SHA384     SW 1444.274 mB/s
HMAC-SHA384     HW   456 mB took 1.004 seconds,  454.236 mB/s Cycles per byte =   7.91
HMAC-SHA384     HW   456 mB took 1.004 seconds,  454.161 mB/s Cycles per byte =   7.91
HMAC-SHA384     HW  908.397 mB/s
HMAC-SHA512     SW   718 mB took 1.001 seconds,  717.627 mB/s Cycles per byte =   5.00
HMAC-SHA512     SW   718 mB took 1.001 seconds,  717.228 mB/s Cycles per byte =   5.01
HMAC-SHA512     SW 1434.855 mB/s
HMAC-SHA512     HW   472 mB took 1.004 seconds,  470.186 mB/s Cycles per byte =   7.64
HMAC-SHA512     HW   472 mB took 1.009 seconds,  467.814 mB/s Cycles per byte =   7.68
HMAC-SHA512     HW  938.000 mB/s
RSA     1024 key gen   SW     40 ops took 1.463 sec, avg 36.573 ms, 27.342 ops/sec
RSA     1024 key gen   SW     40 ops took 1.713 sec, avg 42.819 ms, 23.354 ops/sec
RSA   1024 key gen   SW 50.696 ops/sec
RSA     2048 key gen   SW     40 ops took 9.357 sec, avg 233.918 ms, 4.275 ops/sec
RSA     2048 key gen   SW     40 ops took 9.423 sec, avg 235.584 ms, 4.245 ops/sec
RSA   2048 key gen   SW 8.520 ops/sec
RSA     1024 key gen   HW    160 ops took 1.138 sec, avg 7.111 ms, 140.622 ops/sec
RSA     1024 key gen   HW    160 ops took 1.169 sec, avg 7.305 ms, 136.886 ops/sec
RSA   1024 key gen   HW 277.508 ops/sec
RSA     2048 key gen   HW     40 ops took 1.147 sec, avg 28.664 ms, 34.887 ops/sec
RSA     2048 key gen   HW     40 ops took 1.172 sec, avg 29.306 ms, 34.122 ops/sec
RSA   2048 key gen   HW 69.009 ops/sec
RSA     2048 sign      SW   1200 ops took 1.023 sec, avg 0.852 ms, 1173.290 ops/sec
RSA     2048 sign      SW   1200 ops took 1.023 sec, avg 0.852 ms, 1173.134 ops/sec
RSA   2048 sign      SW 2346.424 ops/sec
RSA     2048 verify    SW  38200 ops took 1.001 sec, avg 0.026 ms, 38143.126 ops/sec
RSA     2048 verify    SW  38200 ops took 1.002 sec, avg 0.026 ms, 38142.136 ops/sec
RSA   2048 verify    SW 76285.262 ops/sec
RSA     2048 sign      HW  18400 ops took 1.002 sec, avg 0.054 ms, 18362.595 ops/sec
RSA     2048 sign      HW  18400 ops took 1.004 sec, avg 0.055 ms, 18334.819 ops/sec
RSA   2048 sign      HW 36697.413 ops/sec
RSA     2048 verify    HW 214000 ops took 1.000 sec, avg 0.005 ms, 213995.102 ops/sec
RSA     2048 verify    HW 214500 ops took 1.000 sec, avg 0.005 ms, 214458.584 ops/sec
RSA   2048 verify    HW 428453.686 ops/sec
DH      2048 key gen   SW   2320 ops took 1.008 sec, avg 0.435 ms, 2300.939 ops/sec
DH      2048 key gen   SW   2320 ops took 1.008 sec, avg 0.435 ms, 2300.524 ops/sec
DH    2048 key gen   SW 4601.463 ops/sec
DH      2048 agree     SW   2300 ops took 1.028 sec, avg 0.447 ms, 2237.185 ops/sec
DH      2048 agree     SW   2300 ops took 1.028 sec, avg 0.447 ms, 2236.690 ops/sec
DH    2048 agree     SW 4473.875 ops/sec
DH      2048 key gen   HW  40840 ops took 1.000 sec, avg 0.024 ms, 40825.341 ops/sec
DH      2048 key gen   HW  40880 ops took 1.001 sec, avg 0.024 ms, 40853.409 ops/sec
DH    2048 key gen   HW 81678.751 ops/sec
DH      2048 agree     HW  42200 ops took 1.000 sec, avg 0.024 ms, 42197.133 ops/sec
DH      2048 agree     HW  42200 ops took 1.001 sec, avg 0.024 ms, 42156.500 ops/sec
DH    2048 agree     HW 84353.632 ops/sec
ECC      256 key gen   SW  65040 ops took 1.000 sec, avg 0.015 ms, 65037.147 ops/sec
ECC      256 key gen   SW  65160 ops took 1.000 sec, avg 0.015 ms, 65147.093 ops/sec
ECC    256 key gen   SW 130184.240 ops/sec
ECDHE    256 agree     SW  16900 ops took 1.005 sec, avg 0.059 ms, 16815.304 ops/sec
ECDHE    256 agree     SW  16900 ops took 1.005 sec, avg 0.059 ms, 16810.016 ops/sec
ECDHE  256 agree     SW 33625.321 ops/sec
ECDSA    256 sign      SW  40600 ops took 1.001 sec, avg 0.025 ms, 40552.267 ops/sec
ECDSA    256 sign      SW  40600 ops took 1.001 sec, avg 0.025 ms, 40550.085 ops/sec
ECDSA  256 sign      SW 81102.352 ops/sec
ECDSA    256 verify    SW  13100 ops took 1.001 sec, avg 0.076 ms, 13085.621 ops/sec
ECDSA    256 verify    SW  13100 ops took 1.001 sec, avg 0.076 ms, 13085.306 ops/sec
ECDSA  256 verify    SW 26170.926 ops/sec
ECDHE    256 agree     HW  26600 ops took 1.000 sec, avg 0.038 ms, 26597.318 ops/sec
ECDHE    256 agree     HW  26700 ops took 1.002 sec, avg 0.038 ms, 26656.256 ops/sec
ECDHE  256 agree     HW 53253.574 ops/sec
ECDSA    256 sign      HW  27700 ops took 1.001 sec, avg 0.036 ms, 27663.230 ops/sec
ECDSA    256 sign      HW  27600 ops took 1.002 sec, avg 0.036 ms, 27545.458 ops/sec
ECDSA  256 sign      HW 55208.689 ops/sec
ECDSA    256 verify    HW  14500 ops took 1.000 sec, avg 0.069 ms, 14493.117 ops/sec
ECDSA    256 verify    HW  14500 ops took 1.003 sec, avg 0.069 ms, 14450.334 ops/sec
ECDSA  256 verify    HW 28943.450 ops/sec
Benchmark complete
IntelQA: Stop
```

### wolfCrypt Benchmark with QAT (single-threaded)

To use the benchmark tool against hardware in single threaded mode build the library with `CFLAGS="-DWC_NO_ASYNC_THREADING"`.

```
sudo ./wolfcrypt/benchmark/benchmark -rsa_sign -dh -ecc
IntelQA: Instances 2
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
`./configure --enable-asynccrypt --with-intelqa=../QAT1.7 --enable-debug --disable-shared CFLAGS="-DQAT_DEBUG" && make`


## Support

For questions or issues email us at support@wolfssl.com.
