# wolfSSL / wolfCrypt Asynchronous Support

This respository contains the async.c and async.h files required for using Asynchronous Cryptography with the wolfSSL library.

* The async.c file goes into `./wolfcrypt/src/`.
* The async.h file goes into `./wolfssl/wolfcrypt/`.

This feature is enabled using:
`./configure --enable-asynccrypt` or `#define WOLFSSL_ASYNC_CRYPT`.

The async crypt simulator is enabled by default if the hardware does not support async crypto or it can be manually enabled using `#define WOLFSSL_ASYNC_CRYPT_TEST`.

## Design
Each crypto alorithm has its own `WC_ASYNC_DEV` structure, which contains a `WOLF_EVENT`, local crypto context and local hardware context.

For SSL/TLS the `WOLF_EVENT` context is the `WOLFSSL*` and the type is `WOLF_EVENT_TYPE_ASYNC_WOLFSSL`. For wolfCrypt operations the `WOLF_EVENT` context is the `WC_ASYNC_DEV*` and the type is `WOLF_EVENT_TYPE_ASYNC_WOLFCRYPT`. 

A generic event system has been created using a `WOLF_EVENT` structure when `HAVE_WOLF_EVENT` is defined. The event structure resides in the `WC_ASYNC_DEV`.

The asyncronous crypto system is modeled after epoll. The implementation uses `wolfSSL_AsyncPoll` or `wolfSSL_CTX_AsyncPoll` to check if any async operations are complete.

## API's

### ```wolfSSL_AsyncPoll```
```
int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags);
```

Polls the provided WOLFSSL object's reference to the WOLFSSL_CTX's event queue to see if any operations outstanding for the WOLFSSL object are done. Return the completed event count on success.

### ```wolfSSL_CTX_AsyncPoll```
```
int wolfSSL_CTX_AsyncPoll(WOLFSSL_CTX* ctx, WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount)
```

Polls the provided WOLFSSL_CTX context event queue to see if any pending events are done. If the `events` argument is provided then a pointer to the `WOLF_EVENT` will be returned up to `maxEvents`. If `eventCount` is provided then the number of events populated will be returned. The `flags` allows for `WOLF_POLL_FLAG_CHECK_HW` to indicate if hardware should be polled again or just return more events.

### ```wolfAsync_DevOpen```
```
int wolfAsync_DevOpen(int *devId);
```

Open the async device and returns an `int` device id for it. 

### ```wolfAsync_DevOpenThread```
```
int wolfAsync_DevOpenThread(int *devId, void* threadId);
```
Opens the async device for a specific thread. A crypto instance is assigned and thread assinity set.

### ```wolfAsync_DevClose```
```
void wolfAsync_DevClose(int *devId)
```

Closes the async device.

### ```wolfAsync_DevCtxInit```
```
int wolfAsync_DevCtxInit(WC_ASYNC_DEV* asyncDev, word32 marker, void* heap, int devId);
```

Initialize the device context and open the device hardware using the provided `WC_ASYNC_DEV ` pointer, marker and device id (from wolfAsync_DevOpen).

### ```wolfAsync_DevCtxFree```
```
void wolfAsync_DevCtxFree(WC_ASYNC_DEV* asyncDev);
```

Closes and free's the device context.


### ```wolfAsync_EventInit```
```
int wolfAsync_EventInit(WOLF_EVENT* event, enum WOLF_EVENT_TYPE type, void* context, word32 flags);
```

Initialize an event structure with provided type and context. Sets the pending flag and the status code to `WC_PENDING_E`. Current flag options are `WC_ASYNC_FLAG_NONE` and `WC_ASYNC_FLAG_CALL_AGAIN` (indicates crypto needs called again after WC_PENDING_E).

### ```wolfAsync_EventWait ```
```
int wolfAsync_EventWait(WOLF_EVENT* event);
```

Waits for the provided event to complete.

### ```wolfAsync_EventPoll```
```
int wolfAsync_EventPoll(WOLF_EVENT* event, WOLF_EVENT_FLAG event_flags);
```

Polls the provided event to determine if its done.

### ```wolfAsync_EventPop ```

```
int wolfAsync_EventPop(WOLF_EVENT* event, enum WOLF_EVENT_TYPE event_type);
```

This will check the event to see if the event type matches and the event is complete. If it is then the async return code is returned. If not then `WC_NOT_PENDING_E` is returned.


### ```wolfAsync_EventQueuePush```
```
int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);
```

Pushes an event to the provided event queue and assigns the provided event.

### ```wolfAsync_EventQueuePoll```
```
int wolfAsync_EventQueuePoll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG event_flags, int* eventCount);
```

Polls all events in the provided event queue. Optionally filters by context. Will return pointers to the done events.

### ```wc_AsyncHandle```
```
int wc_AsyncHandle(WC_ASYNC_DEV* asyncDev, WOLF_EVENT_QUEUE* queue, word32 flags);
```

This will push the event inside asyncDev into the provided queue.

### ```wc_AsyncWait```    
```    
int wc_AsyncWait(int ret, WC_ASYNC_DEV* asyncDev, word32 flags);
```

This will wait until the provided asyncDev is done (or error).

### ```wolfAsync_HardwareStart```
```
int wolfAsync_HardwareStart(void);
```

If using multiple threads this allows a way to start the hardware before using `wolfAsync_DevOpen` to ensure the memory system is setup. Ensure that `wolfAsync_HardwareStop` is called on exit. Internally there is a start/stop counter, so this can be called multiple times, but stop must also be called the same number of times to shutdown the hardware.

### ```wolfAsync_HardwareStop```
```
void wolfAsync_HardwareStop(void);
```

Stops hardware if internal `--start_count == 0`.

# Examples
## TLS Server Example

```
#ifdef WOLFSSL_ASYNC_CRYPT
    static int devId = INVALID_DEVID;

    ret = wolfAsync_DevOpen(&devId);
    if (ret != 0) {
        err_sys("Async device open failed");
    }
    wolfSSL_CTX_UseAsync(ctx, devId);
#endif /* WOLFSSL_ASYNC_CRYPT */

	err = 0;
	do {
	#ifdef WOLFSSL_ASYNC_CRYPT
	    if (err == WC_PENDING_E) {
	       ret = wolfSSL_AsyncPoll(ssl);
	       if (ret < 0) { break; } else if (ret == 0) { continue; }
	    }
	#endif
	
	    ret = wolfSSL_accept(ssl);
	    if (ret != SSL_SUCCESS) {
	        err = wolfSSL_get_error(ssl, 0);
	    }
	} while (ret != SSL_SUCCESS && err == WC_PENDING_E);
    
#ifdef WOLFSSL_ASYNC_CRYPT
    wolfAsync_DevClose(&devId);
#endif
```

## wolfCrypt Example

```
#ifdef WOLFSSL_ASYNC_CRYPT
    static int devId = INVALID_DEVID;

    ret = wolfAsync_DevOpen(&devId);
    if (ret != 0) {
        err_sys("Async device open failed");
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

	RsaKey key;
	ret = wc_InitRsaKey_ex(&key, HEAP_HINT, devId);
	
	ret = wc_RsaPrivateKeyDecode(tmp, &idx, &key, (word32)bytes);
	
	do {
#if defined(WOLFSSL_ASYNC_CRYPT)
        ret = wc_AsyncWait(ret, &key.asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
#endif
        if (ret >= 0) {
            ret = wc_RsaPublicEncrypt(in, inLen, out, outSz, &key, &rng);
        }
    } while (ret == WC_PENDING_E);
    if (ret < 0) {
        err_sys("RsaPublicEncrypt operation failed");
    }
    
#ifdef WOLFSSL_ASYNC_CRYPT
    wolfAsync_DevClose(&devId);
#endif
```

## Benchmarks

```
./configure --enable-certgen --enable-certext --enable-keygen --enable-certreq --enable-ecc --enable-supportedcurves --enable-asynccrypt --enable-aesgcm --enable-intelasm --enable-aesni --enable-des3 --enable-sha224 --enable-opensslextra --enable-psk --with-intelqa=../QAT1.6 C_EXTRA_FLAGS="-DWC_ASYNC_THRESH_NONE"
make
sudo ./wolfcrypt/benchmark/benchmark

IntelQA: Instances 6
wolfCrypt Benchmark (min 1.0 sec each)
CPUs: 8

```

# Build Options

1. `WC_NO_ASYNC_THREADING`: Disables async mult-threading.
2. `WC_ASYNC_THREAD_BIND`: Enables binding of thread to crypto hardware instance.
2. `WC_ASYNC_THRESH_NONE` Disables the cipher thresholds, which are tunable values to determine at what size hardware should be used vs. software.
3. `NO_SW_BENCH`: Disables sofware benchmarks so only hardware results are returned.
4. Use `WOLFSSL_DEBUG_MEMORY` and `WOLFSSL_TRACK_MEMORY` to help debug memory issues.


# References

## TLS Client/Server Async Example

We have a full TLS client/server async examples here:

* [https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tls-epoll-perf.c](https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/server-tls-epoll-perf.c)

* [https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/client-tls-perf.c](https://github.com/wolfSSL/wolfssl-examples/blob/master/tls/client-tls-perf.c)

### Usage
```
git clone git@github.com:wolfSSL/wolfssl-examples.git
cd wolfssl-examples
cd tls
make
sudo ./server-tls-epoll-perf
sudo ./client-tls-perf
```

```
Waiting for a connection...
SSL cipher suite is TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
wolfSSL Client Benchmark 16384 bytes
	Num Conns         :       100
	Total             :   777.080 ms
	Total Avg         :     7.771 ms
	t/s               :   128.687
	Accept            :   590.556 ms
	Accept Avg        :     5.906 ms
	Total Read bytes  :   1638400 bytes
	Total Write bytes :   1638400 bytes
	Read              :    73.360 ms (   21.299 MBps)
	Write             :    74.535 ms (   20.963 MBps)
```

# Installation

If using wolfAsyncCrypt repo directly some useful commands to setup links to wolfssl in relative directory:

## Async Files
```
rm wolfcrypt/src/async.c
ln -s ../../../wolfAsyncCrypt/wolfcrypt/src/async.c ./wolfcrypt/src/async.c
rm wolfssl/wolfcrypt/async.h 
ln -s ../../../wolfAsyncCrypt/wolfssl/wolfcrypt/async.h ./wolfssl/wolfcrypt/async.h
```

## Intel QuickAssist Port Files
```
rm wolfcrypt/src/port/intel/quickassist.c
ln -s ../../../../../wolfAsyncCrypt/wolfcrypt/src/port/intel/quickassist.c ./wolfcrypt/src/port/intel/quickassist.c
rm wolfcrypt/src/port/intel/quickassist_mem.c
ln -s ../../../../../wolfAsyncCrypt/wolfcrypt/src/port/intel/quickassist_mem.c ./wolfcrypt/src/port/intel/quickassist_mem.c

mkdir wolfssl/wolfcrypt/port/intel
rm wolfssl/wolfcrypt/port/intel/quickassist.h
ln -s ../../../../../wolfAsyncCrypt/wolfssl/wolfcrypt/port/intel/quickassist.h ./wolfssl/wolfcrypt/port/intel/quickassist.h
rm wolfssl/wolfcrypt/port/intel/quickassist_mem.h
ln -s ../../../../../wolfAsyncCrypt/wolfssl/wolfcrypt/port/intel/quickassist_mem.h ./wolfssl/wolfcrypt/port/intel/quickassist_mem.h

rm wolfcrypt/src/port/intel/README.md
ln -s ../../../../../wolfAsyncCrypt/wolfcrypt/src/port/intel/README.md ./wolfcrypt/src/port/intel/README.md
```

## Cavium Nitrox Port Files
```
rm wolfcrypt/src/port/cavium/cavium_nitrox.c
ln -s ../../../../../wolfAsyncCrypt/wolfcrypt/src/port/cavium/cavium_nitrox.c ./wolfcrypt/src/port/cavium/cavium_nitrox.c

mkdir wolfssl/wolfcrypt/port/cavium
rm ./wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h
ln -s ../../../../../wolfAsyncCrypt/wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h ./wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h

rm wolfcrypt/src/port/cavium/README.md
ln -s ../../../../../wolfAsyncCrypt/wolfcrypt/src/port/cavium/README.md ./wolfcrypt/src/port/cavium/README.md
```

Then a wolfssl `make dist` will include actual files.
