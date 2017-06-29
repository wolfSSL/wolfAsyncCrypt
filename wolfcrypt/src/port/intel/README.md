# Intel QuickAssist Adapter Asynchronous Support

The wolfSSL / wolfCrypt libraries support hardware crypto acceleration using the Intel QuickAssist adapter. This software has been tested using QAT 1.6 in user space on Cent OS (Kernel 3.10.0-327.22.2.el7.x86_64) on an Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz. Intel QuickAssist is DH895xCC (BDF=03:00.0, Stepping A0, device 0 is SKU2).

## Overview

Support has been added for wolfCrypt for RSA public/private (CRT/non-CRT), AES CBC/GCM, ECDH/ECDSA, DH, DES3, SHA, SHA224, SHA256, SHA384, SHA512, MD5 and HMAC. RSA padding is done via software. The wolfCrypt tests and benchmarks have asynchronous. The wolfCrypt benchmark tool support multi-threading. The wolfSSL SSL/TLS async support has been extended to include all PKI, Encryption/Decryption and hashing/HMAC. An async hardware simulator has been added to test the asyncronous support without hardware.

The Intel QuickAssist port files are located in `wolfcrypt/src/port/intel/quickassist.c` and `wolfssl/wolfcrypt/port/intel/quickassist.h`. The QuickAssist memory handling for NUMA and normal malloc is in `wolfcrypt/src/port/intel/quickassist_mem.c`.

The asynchronous crypto files are located at `wolfcrypt/src/async.c` and `wolfssl/wolfcrypt/async.h`. These files are not in the public repository. Please contact info@wolfssl.com if interested in our asynchronous support to request an evalation.


## Building

1. Setup `QAT1.6` and `wolfssl` next to each other in the same folder.
2. Build the QAT 1.6:
  * Run the installer using `sudo ./installer.sh`
  * Choose option 3 to install.
  * After reboot you'll need to make sure and load the qaeMemDrv.ko module. `sudo insmod ./QAT1.6/build/qaeMemDrv.ko`
3. Build wolfSSL:
  * `./configure --enable-asynccrypt --with-intelqa=../QAT1.6 && make`
4. Note: `sudo make check` will fail since default QAT configuration doesn't allow multiple concurrent processes to use hardware. You can run each of the make check scripts indidually with sudo. The hardware configuration can be customized by editing the `QAT1.6/build/dh895xcc_qa_dev0.conf` file to allow multiple processes.

## Usage

Running wolfCrypt test and benchmark must be done with `sudo` to allow hardware access. By default the QuickAssist code uses the "SSL" process name via `QAT_PROCESS_NAME` in quickassist.h to match up to the hardware configuration.

Here are some build options for tuning your use:

1. `QAT_USE_POLLING_CHECK`: Enables polling check to ensure only one poll per crypto instance.
2. `WC_ASYNC_THREAD_BIND`: Enables binding of thread to crypto hardware instance.
3. `WOLFSSL_DEBUG_MEMORY_PRINT`: Enables verbose malloc/free printing. This option is used along with `WOLFSSL_DEBUG_MEMORY` and `WOLFSSL_TRACK_MEMORY`.

The QuickAssist driver uses its own memory management system in `quickassist_mem.c`. This can be tuned using the following defines:

1. `USE_QAE_STATIC_MEM`: Uses a global pool for the list of allocations. This improves performance, but consumes extra up front memory. The pre-allocation size can be tuned using `QAE_USER_MEM_MAX_COUNT`.
2. `USE_QAE_THREAD_LS` : Uses thread-local-storage and removes the mutex. Can improve performance in multi-threaded environment, but does use extra memeory.


### wolfCrypt Test with QAT
```
sudo ./wolfcrypt/test/testwolfcrypt
IntelQA: Instances 6
RSA      test passed!
```

### wolfCrypt Benchmark with QAT (multi-threaded)

Multiple concurrent threads will be started based on the number of QuickAssist crypto instances available. If you want to exclude the software benchmarks use `./configure C_EXTRA_FLAGS="-DNO_SW_BENCH"`.

```
sudo ./wolfcrypt/benchmark/benchmark
IntelQA: Instances 6
wolfCrypt Benchmark (min 1.0 sec each)
CPUs: 6
RSA 2048 public HW    35668 ops took 1.002 sec, avg 0.028 ms, 35610.386 ops/sec
RSA 2048 public HW    35861 ops took 1.002 sec, avg 0.028 ms, 35778.027 ops/sec
RSA 2048 public HW    27443 ops took 1.005 sec, avg 0.037 ms, 27312.497 ops/sec
RSA 2048 public HW    26984 ops took 1.008 sec, avg 0.037 ms, 26778.262 ops/sec
RSA 2048 public HW    26595 ops took 1.005 sec, avg 0.038 ms, 26452.160 ops/sec
RSA 2048 public HW    26501 ops took 1.005 sec, avg 0.038 ms, 26367.950 ops/sec
RSA 2048 private HW    6992 ops took 1.007 sec, avg 0.144 ms, 6945.720 ops/sec
RSA 2048 private HW    6986 ops took 1.010 sec, avg 0.145 ms, 6913.791 ops/sec
RSA 2048 private HW    6886 ops took 1.006 sec, avg 0.146 ms, 6843.175 ops/sec
RSA 2048 private HW    6890 ops took 1.006 sec, avg 0.146 ms, 6850.390 ops/sec
RSA 2048 private HW    6984 ops took 1.008 sec, avg 0.144 ms, 6929.080 ops/sec
RSA 2048 private HW    6986 ops took 1.007 sec, avg 0.144 ms, 6936.804 ops/sec
IntelQA: Stop
```

### wolfCrypt Benchmark with QAT (single-threaded)

To use the benchmark tool against hardware in single threaded mode build the library with `./configure C_EXTRA_FLAGS="-DDWC_NO_ASYNC_THREADING"`.

```
sudo ./wolfcrypt/benchmark/benchmark
IntelQA: Instances 6
wolfCrypt Benchmark (min 1.0 sec each)
RSA 2048 public SW     3500 ops took 1.005 sec, avg 0.287 ms, 3480.862 ops/sec
RSA 2048 private SW     300 ops took 1.056 sec, avg 3.521 ms, 284.005 ops/sec
RSA 2048 public HW    116801 ops took 1.000 sec, avg 0.009 ms, 116796.545 ops/sec
RSA 2048 private HW   18522 ops took 1.003 sec, avg 0.054 ms, 18467.763 ops/sec
IntelQA: Stop
```

### wolfSSL Asynchronous Test Mode

Enable asynccrypt alone to use async simulator.
`./configure --enable-asynccrypt`


## Debugging

To enable debug messages:
`./configure --enable-asynccrypt --with-intelqa=../QAT1.6 --enable-debug --disable-shared C_EXTRA_FLAGS="-DQAT_DEBUG" && make`


