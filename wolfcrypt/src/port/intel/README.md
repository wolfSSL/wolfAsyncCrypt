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
* `QAT_HASH_ENABLE_PARTIAL`: Enables partial hashing support, which allows sending blocks to hardware prior to final. Otherwise all hash updates are cached.

### wolfCrypt Test with QAT
```
sudo ./wolfcrypt/test/testwolfcrypt
IntelQA: Instances 6
RSA      test passed!
```

### wolfCrypt Benchmark with QAT 8970 (multi-threaded)

Multiple concurrent threads will be started based on the number of CPU's available. If you want to exclude the software benchmarks use `./configure CFLAGS="-DNO_SW_BENCH"`.

```
./configure --with-intelqa=../QAT1.7 --enable-asynccrypt --enable-sp --enable-sp-asm --enable-aesni --enable-intelasm --enable-keygen --enable-sha3
make
sudo ./wolfcrypt/benchmark/benchmark
IntelQA: Instances 18
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
CPUs: 8
...
SHA3-256        SW   115 MB took 1.034 seconds,  111.256 MB/s Cycles per byte =  29.08
SHA3-256        SW   115 MB took 1.034 seconds,  111.251 MB/s Cycles per byte =  29.08
SHA3-256        SW   115 MB took 1.034 seconds,  111.191 MB/s Cycles per byte =  29.10
SHA3-256        SW   115 MB took 1.037 seconds,  110.850 MB/s Cycles per byte =  29.18
SHA3-256        SW   115 MB took 1.038 seconds,  110.822 MB/s Cycles per byte =  29.19
SHA3-256        SW   115 MB took 1.038 seconds,  110.802 MB/s Cycles per byte =  29.20
SHA3-256        SW   115 MB took 1.038 seconds,  110.795 MB/s Cycles per byte =  29.20
SHA3-256        SW   115 MB took 1.039 seconds,  110.666 MB/s Cycles per byte =  29.23
SHA3-256    SW  887.633 MB/s
SHA3-256        HW   335 MB took 1.001 seconds,  334.571 MB/s Cycles per byte =   9.67
SHA3-256        HW   315 MB took 1.002 seconds,  314.254 MB/s Cycles per byte =  10.29
SHA3-256        HW   310 MB took 1.005 seconds,  308.376 MB/s Cycles per byte =  10.49
SHA3-256        HW   320 MB took 1.007 seconds,  317.683 MB/s Cycles per byte =  10.18
SHA3-256        HW   320 MB took 1.008 seconds,  317.548 MB/s Cycles per byte =  10.19
SHA3-256        HW   320 MB took 1.009 seconds,  317.122 MB/s Cycles per byte =  10.20
SHA3-256        HW   320 MB took 1.009 seconds,  317.050 MB/s Cycles per byte =  10.20
SHA3-256        HW   335 MB took 1.009 seconds,  331.931 MB/s Cycles per byte =   9.75
SHA3-256    HW 2558.535 MB/s
...
RSA     1024 key gen   SW     15 ops took 1.278 sec, avg 85.189 ms, 11.739 ops/sec
RSA     1024 key gen   SW     15 ops took 1.355 sec, avg 90.326 ms, 11.071 ops/sec
RSA     1024 key gen   SW     15 ops took 1.677 sec, avg 111.796 ms, 8.945 ops/sec
RSA     1024 key gen   SW     15 ops took 1.709 sec, avg 113.926 ms, 8.778 ops/sec
RSA     1024 key gen   SW     15 ops took 1.721 sec, avg 114.742 ms, 8.715 ops/sec
RSA     1024 key gen   SW     15 ops took 1.856 sec, avg 123.703 ms, 8.084 ops/sec
RSA     1024 key gen   SW     15 ops took 1.874 sec, avg 124.955 ms, 8.003 ops/sec
RSA     1024 key gen   SW     15 ops took 1.903 sec, avg 126.886 ms, 7.881 ops/sec
RSA   1024 key gen   SW 73.215 ops/sec
RSA     2048 key gen   SW     15 ops took 6.716 sec, avg 447.756 ms, 2.233 ops/sec
RSA     2048 key gen   SW     15 ops took 8.105 sec, avg 540.318 ms, 1.851 ops/sec
RSA     2048 key gen   SW     15 ops took 8.248 sec, avg 549.878 ms, 1.819 ops/sec
RSA     2048 key gen   SW     15 ops took 8.499 sec, avg 566.602 ms, 1.765 ops/sec
RSA     2048 key gen   SW     15 ops took 8.591 sec, avg 572.705 ms, 1.746 ops/sec
RSA     2048 key gen   SW     15 ops took 8.691 sec, avg 579.383 ms, 1.726 ops/sec
RSA     2048 key gen   SW     15 ops took 9.260 sec, avg 617.353 ms, 1.620 ops/sec
RSA     2048 key gen   SW     15 ops took 9.296 sec, avg 619.711 ms, 1.614 ops/sec
RSA   2048 key gen   SW 14.373 ops/sec
RSA     1024 key gen   HW     60 ops took 1.003 sec, avg 16.710 ms, 59.846 ops/sec
RSA     1024 key gen   HW     60 ops took 1.035 sec, avg 17.246 ms, 57.986 ops/sec
RSA     1024 key gen   HW     60 ops took 1.057 sec, avg 17.610 ms, 56.785 ops/sec
RSA     1024 key gen   HW     60 ops took 1.084 sec, avg 18.072 ms, 55.334 ops/sec
RSA     1024 key gen   HW     60 ops took 1.097 sec, avg 18.275 ms, 54.718 ops/sec
RSA     1024 key gen   HW    120 ops took 1.107 sec, avg 9.223 ms, 108.423 ops/sec
RSA     1024 key gen   HW    120 ops took 1.110 sec, avg 9.246 ms, 108.152 ops/sec
RSA     1024 key gen   HW     60 ops took 1.135 sec, avg 18.918 ms, 52.860 ops/sec
RSA   1024 key gen   HW 554.104 ops/sec
RSA     2048 key gen   HW     15 ops took 1.016 sec, avg 67.722 ms, 14.766 ops/sec
RSA     2048 key gen   HW     15 ops took 1.027 sec, avg 68.458 ms, 14.607 ops/sec
RSA     2048 key gen   HW     15 ops took 1.150 sec, avg 76.651 ms, 13.046 ops/sec
RSA     2048 key gen   HW     15 ops took 1.166 sec, avg 77.736 ms, 12.864 ops/sec
RSA     2048 key gen   HW     45 ops took 1.434 sec, avg 31.864 ms, 31.383 ops/sec
RSA     2048 key gen   HW     45 ops took 1.457 sec, avg 32.371 ms, 30.892 ops/sec
RSA     2048 key gen   HW     30 ops took 1.556 sec, avg 51.881 ms, 19.275 ops/sec
RSA     2048 key gen   HW     30 ops took 1.594 sec, avg 53.145 ms, 18.816 ops/sec
RSA   2048 key gen   HW 155.651 ops/sec
RSA     2048 public    SW   2300 ops took 1.025 sec, avg 0.445 ms, 2244.936 ops/sec
RSA     2048 public    SW   2300 ops took 1.025 sec, avg 0.446 ms, 2243.587 ops/sec
RSA     2048 public    SW   2300 ops took 1.026 sec, avg 0.446 ms, 2241.047 ops/sec
RSA     2048 public    SW   2300 ops took 1.026 sec, avg 0.446 ms, 2240.816 ops/sec
RSA     2048 public    SW   2300 ops took 1.027 sec, avg 0.447 ms, 2239.092 ops/sec
RSA     2048 public    SW   2300 ops took 1.028 sec, avg 0.447 ms, 2236.956 ops/sec
RSA     2048 public    SW   2300 ops took 1.029 sec, avg 0.447 ms, 2235.893 ops/sec
RSA     2048 public    SW   2300 ops took 1.030 sec, avg 0.448 ms, 2233.920 ops/sec
RSA   2048 public    SW 17916.247 ops/sec
RSA     2048 private   SW    500 ops took 1.057 sec, avg 2.113 ms, 473.171 ops/sec
RSA     2048 private   SW    500 ops took 1.057 sec, avg 2.114 ms, 473.113 ops/sec
RSA     2048 private   SW    500 ops took 1.057 sec, avg 2.114 ms, 472.983 ops/sec
RSA     2048 private   SW    500 ops took 1.061 sec, avg 2.123 ms, 471.033 ops/sec
RSA     2048 private   SW    500 ops took 1.067 sec, avg 2.135 ms, 468.448 ops/sec
RSA     2048 private   SW    500 ops took 1.068 sec, avg 2.135 ms, 468.351 ops/sec
RSA     2048 private   SW    500 ops took 1.068 sec, avg 2.135 ms, 468.339 ops/sec
RSA     2048 private   SW    500 ops took 1.068 sec, avg 2.135 ms, 468.305 ops/sec
RSA   2048 private   SW 3763.743 ops/sec
RSA     2048 public    HW   2200 ops took 1.000 sec, avg 0.455 ms, 2199.903 ops/sec
RSA     2048 public    HW   2200 ops took 1.002 sec, avg 0.455 ms, 2196.578 ops/sec
RSA     2048 public    HW   2200 ops took 1.002 sec, avg 0.455 ms, 2195.504 ops/sec
RSA     2048 public    HW   2200 ops took 1.002 sec, avg 0.455 ms, 2195.751 ops/sec
RSA     2048 public    HW   2300 ops took 1.022 sec, avg 0.444 ms, 2251.333 ops/sec
RSA     2048 public    HW   2300 ops took 1.023 sec, avg 0.445 ms, 2248.667 ops/sec
RSA     2048 public    HW   2300 ops took 1.023 sec, avg 0.445 ms, 2248.274 ops/sec
RSA     2048 public    HW   2300 ops took 1.023 sec, avg 0.445 ms, 2248.373 ops/sec
RSA   2048 public    HW 17784.383 ops/sec
RSA     2048 private   HW   5400 ops took 1.002 sec, avg 0.186 ms, 5389.201 ops/sec
RSA     2048 private   HW   5400 ops took 1.005 sec, avg 0.186 ms, 5372.129 ops/sec
RSA     2048 private   HW   5500 ops took 1.006 sec, avg 0.183 ms, 5467.110 ops/sec
RSA     2048 private   HW   5500 ops took 1.008 sec, avg 0.183 ms, 5458.142 ops/sec
RSA     2048 private   HW   5400 ops took 1.009 sec, avg 0.187 ms, 5354.227 ops/sec
RSA     2048 private   HW   5900 ops took 1.010 sec, avg 0.171 ms, 5844.392 ops/sec
RSA     2048 private   HW   6000 ops took 1.011 sec, avg 0.169 ms, 5934.197 ops/sec
RSA     2048 private   HW   5500 ops took 1.011 sec, avg 0.184 ms, 5439.701 ops/sec
RSA   2048 private   HW 44259.097 ops/sec
DH      2048 key gen   SW    930 ops took 1.004 sec, avg 1.080 ms, 925.881 ops/sec
DH      2048 key gen   SW    930 ops took 1.005 sec, avg 1.081 ms, 925.165 ops/sec
DH      2048 key gen   SW    930 ops took 1.008 sec, avg 1.084 ms, 922.597 ops/sec
DH      2048 key gen   SW    930 ops took 1.009 sec, avg 1.085 ms, 921.692 ops/sec
DH      2048 key gen   SW    945 ops took 1.009 sec, avg 1.068 ms, 936.241 ops/sec
DH      2048 key gen   SW    945 ops took 1.011 sec, avg 1.070 ms, 934.686 ops/sec
DH      2048 key gen   SW    930 ops took 1.012 sec, avg 1.088 ms, 919.082 ops/sec
DH      2048 key gen   SW    960 ops took 1.015 sec, avg 1.057 ms, 946.100 ops/sec
DH    2048 key gen   SW 7431.443 ops/sec
DH      2048 agree     SW   1000 ops took 1.077 sec, avg 1.077 ms, 928.079 ops/sec
DH      2048 agree     SW   1000 ops took 1.078 sec, avg 1.078 ms, 927.998 ops/sec
DH      2048 agree     SW   1000 ops took 1.078 sec, avg 1.078 ms, 927.821 ops/sec
DH      2048 agree     SW   1000 ops took 1.083 sec, avg 1.083 ms, 923.112 ops/sec
DH      2048 agree     SW   1000 ops took 1.086 sec, avg 1.086 ms, 920.944 ops/sec
DH      2048 agree     SW   1000 ops took 1.086 sec, avg 1.086 ms, 920.911 ops/sec
DH      2048 agree     SW   1000 ops took 1.086 sec, avg 1.086 ms, 920.873 ops/sec
DH      2048 agree     SW   1000 ops took 1.086 sec, avg 1.086 ms, 920.826 ops/sec
DH    2048 agree     SW 7390.564 ops/sec
DH      2048 key gen   HW   5685 ops took 1.000 sec, avg 0.176 ms, 5682.897 ops/sec
DH      2048 key gen   HW   5745 ops took 1.001 sec, avg 0.174 ms, 5741.136 ops/sec
DH      2048 key gen   HW   5745 ops took 1.001 sec, avg 0.174 ms, 5740.987 ops/sec
DH      2048 key gen   HW   5700 ops took 1.001 sec, avg 0.176 ms, 5694.579 ops/sec
DH      2048 key gen   HW   5730 ops took 1.001 sec, avg 0.175 ms, 5722.098 ops/sec
DH      2048 key gen   HW   5685 ops took 1.002 sec, avg 0.176 ms, 5675.583 ops/sec
DH      2048 key gen   HW   5745 ops took 1.002 sec, avg 0.174 ms, 5735.627 ops/sec
DH      2048 key gen   HW   5745 ops took 1.002 sec, avg 0.174 ms, 5733.504 ops/sec
DH    2048 key gen   HW 45726.411 ops/sec
DH      2048 agree     HW  11700 ops took 1.003 sec, avg 0.086 ms, 11667.390 ops/sec
DH      2048 agree     HW  11300 ops took 1.003 sec, avg 0.089 ms, 11263.484 ops/sec
DH      2048 agree     HW  10800 ops took 1.005 sec, avg 0.093 ms, 10743.382 ops/sec
DH      2048 agree     HW  11100 ops took 1.006 sec, avg 0.091 ms, 11033.854 ops/sec
DH      2048 agree     HW  11600 ops took 1.006 sec, avg 0.087 ms, 11526.690 ops/sec
DH      2048 agree     HW  11400 ops took 1.007 sec, avg 0.088 ms, 11315.866 ops/sec
DH      2048 agree     HW  11500 ops took 1.007 sec, avg 0.088 ms, 11414.709 ops/sec
DH      2048 agree     HW  11000 ops took 1.008 sec, avg 0.092 ms, 10911.443 ops/sec
DH    2048 agree     HW 89876.817 ops/sec
ECC      256 key gen   SW   7905 ops took 1.000 sec, avg 0.127 ms, 7904.533 ops/sec
ECC      256 key gen   SW   7905 ops took 1.000 sec, avg 0.127 ms, 7904.327 ops/sec
ECC      256 key gen   SW   7905 ops took 1.000 sec, avg 0.127 ms, 7904.470 ops/sec
ECC      256 key gen   SW   7905 ops took 1.000 sec, avg 0.127 ms, 7902.811 ops/sec
ECC      256 key gen   SW   7875 ops took 1.000 sec, avg 0.127 ms, 7871.175 ops/sec
ECC      256 key gen   SW   7920 ops took 1.001 sec, avg 0.126 ms, 7914.579 ops/sec
ECC      256 key gen   SW   7875 ops took 1.001 sec, avg 0.127 ms, 7869.366 ops/sec
ECC      256 key gen   SW   7890 ops took 1.001 sec, avg 0.127 ms, 7883.189 ops/sec
ECC    256 key gen   SW 63154.449 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.003 sec, avg 0.145 ms, 6881.166 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.003 sec, avg 0.145 ms, 6880.829 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.003 sec, avg 0.145 ms, 6879.376 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.008 sec, avg 0.146 ms, 6848.431 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.008 sec, avg 0.146 ms, 6847.228 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.008 sec, avg 0.146 ms, 6847.908 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.008 sec, avg 0.146 ms, 6847.629 ops/sec
ECDHE    256 agree     SW   6900 ops took 1.008 sec, avg 0.146 ms, 6846.908 ops/sec
ECDHE  256 agree     SW 54879.476 ops/sec
ECDSA    256 sign      SW   7200 ops took 1.004 sec, avg 0.139 ms, 7174.823 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.010 sec, avg 0.138 ms, 7230.071 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.010 sec, avg 0.138 ms, 7227.559 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.011 sec, avg 0.138 ms, 7223.610 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.011 sec, avg 0.138 ms, 7221.317 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.012 sec, avg 0.139 ms, 7214.864 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.012 sec, avg 0.139 ms, 7214.444 ops/sec
ECDSA    256 sign      SW   7300 ops took 1.012 sec, avg 0.139 ms, 7214.152 ops/sec
ECDSA  256 sign      SW 57720.841 ops/sec
ECDSA    256 verify    SW   5300 ops took 1.001 sec, avg 0.189 ms, 5293.405 ops/sec
ECDSA    256 verify    SW   5400 ops took 1.007 sec, avg 0.187 ms, 5361.201 ops/sec
ECDSA    256 verify    SW   5400 ops took 1.008 sec, avg 0.187 ms, 5356.182 ops/sec
ECDSA    256 verify    SW   5400 ops took 1.012 sec, avg 0.187 ms, 5335.311 ops/sec
ECDSA    256 verify    SW   5400 ops took 1.013 sec, avg 0.188 ms, 5329.413 ops/sec
ECDSA    256 verify    SW   5500 ops took 1.013 sec, avg 0.184 ms, 5427.822 ops/sec
ECDSA    256 verify    SW   5500 ops took 1.015 sec, avg 0.184 ms, 5420.477 ops/sec
ECDSA    256 verify    SW   5500 ops took 1.016 sec, avg 0.185 ms, 5415.513 ops/sec
ECDSA  256 verify    SW 42939.323 ops/sec
ECDHE    256 agree     HW   7100 ops took 1.000 sec, avg 0.141 ms, 7098.238 ops/sec
ECDHE    256 agree     HW   6700 ops took 1.000 sec, avg 0.149 ms, 6698.071 ops/sec
ECDHE    256 agree     HW   7200 ops took 1.001 sec, avg 0.139 ms, 7189.648 ops/sec
ECDHE    256 agree     HW   7100 ops took 1.003 sec, avg 0.141 ms, 7077.374 ops/sec
ECDHE    256 agree     HW   7100 ops took 1.004 sec, avg 0.141 ms, 7069.122 ops/sec
ECDHE    256 agree     HW   6600 ops took 1.006 sec, avg 0.152 ms, 6562.991 ops/sec
ECDHE    256 agree     HW   7000 ops took 1.006 sec, avg 0.144 ms, 6956.743 ops/sec
ECDHE    256 agree     HW   6500 ops took 1.007 sec, avg 0.155 ms, 6456.951 ops/sec
ECDHE  256 agree     HW 55109.138 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.000 sec, avg 0.145 ms, 6899.808 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.000 sec, avg 0.145 ms, 6898.689 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.000 sec, avg 0.145 ms, 6897.497 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.001 sec, avg 0.145 ms, 6895.745 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.002 sec, avg 0.145 ms, 6889.583 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.002 sec, avg 0.145 ms, 6888.489 ops/sec
ECDSA    256 sign      HW   6900 ops took 1.003 sec, avg 0.145 ms, 6882.711 ops/sec
ECDSA    256 sign      HW   7000 ops took 1.006 sec, avg 0.144 ms, 6957.988 ops/sec
ECDSA  256 sign      HW 55210.509 ops/sec
ECDSA    256 verify    HW   5300 ops took 1.001 sec, avg 0.189 ms, 5296.473 ops/sec
ECDSA    256 verify    HW   5400 ops took 1.002 sec, avg 0.186 ms, 5389.679 ops/sec
ECDSA    256 verify    HW   5400 ops took 1.003 sec, avg 0.186 ms, 5386.383 ops/sec
ECDSA    256 verify    HW   5400 ops took 1.008 sec, avg 0.187 ms, 5356.064 ops/sec
ECDSA    256 verify    HW   5500 ops took 1.009 sec, avg 0.183 ms, 5452.357 ops/sec
ECDSA    256 verify    HW   5500 ops took 1.011 sec, avg 0.184 ms, 5442.624 ops/sec
ECDSA    256 verify    HW   5400 ops took 1.012 sec, avg 0.187 ms, 5337.931 ops/sec
ECDSA    256 verify    HW   5400 ops took 1.014 sec, avg 0.188 ms, 5328.019 ops/sec
ECDSA  256 verify    HW 42989.530 ops/sec
IntelQA: Stop
```

### wolfCrypt Benchmark with QAT (single-threaded)

To use the benchmark tool against hardware in single threaded mode build the library with `./configure CFLAGS="-DWC_NO_ASYNC_THREADING"`.

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
