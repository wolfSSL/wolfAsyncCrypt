# wolfAsyncCrypt

This respository contains the async.c and async.h files required for using Asynchronous Cryptography with the wolfSSL library.

* The async.c file goes into `./wolfcrypt/src/`.
* The async.h file goes into `./wolfssl/wolfcrypt/`.

This feature is enabled using:
`./configure --enable-asynccrypt` or `#define WOLFSSL_ASYNC_CRYPT`.

The async crypt simulator is enabled by default if the hardware does not support async crypto or it can be manually enabled using `#define WOLFSSL_ASYNC_CRYPT_TEST`.

## Design
A generic event system has been created using a `WOLF_EVENT` structure. If `HAVE_WOLF_EVENT` is defined then the `WOLFSSL` structure inclues a generic `WOLF_EVENT` for uses specific to that SSL connection.

The asyncronous crypto system is modeled after epoll. The implementation uses `wolfSSL_AsyncPoll` to check if any async operations are complete.

## API's

### ```wolfSSL_AsyncPoll```
```
int wolfSSL_AsyncPoll(WOLFSSL* ssl, WOLF_EVENT_FLAG flags);
```

Polls the provided WOLFSSL object's event to see if its done. Return 1 on success.

### ```wolfSSL_CTX_AsyncPoll```
```
int wolfSSL_CTX_AsyncPoll(WOLFSSL_CTX* ctx, WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount);
```

Polls the provided WOLFSSL_CTX context queue to see if any pending events are done.

### ```wolfAsync_DevOpen```
```
int wolfAsync_DevOpen(int *devId);
```

Open the async device and returns an `int` device id for it.

### ```wolfAsync_DevClose```
```
void wolfAsync_DevClose(int *devId)
```

Closes the async device.

### ```wolfAsync_DevCtxInit```
```
int wolfAsync_DevCtxInit(AsyncCryptDev* asyncDev, int marker, int devId);
```

Initialize the device context and open the device hardware using the provided `AsyncCryptDev` pointer, marker and device id (from wolfAsync_DevOpen).

### ```wolfAsync_DevCtxFree```
```
void wolfAsync_DevCtxFree(AsyncCryptDev* asyncDev);
```

Closes and free's the device context.



### ```wolfAsync_EventPop ```

```
int wolfAsync_EventPop(WOLF_EVENT* event, enum WOLF_EVENT_TYPE event_type);
```

This will check the event to see if the event type matches and the event is complete. If it is then the async return code is returned.


### ```wolfAsync_EventQueuePush```
```
int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event, 
    enum WOLF_EVENT_TYPE event_type, void* context);
```

Pushes an event to the provided event queue and assigns the provided event type and context.

### ```wolfAsync_EventPoll```
```
int wolfAsync_EventPoll(WOLF_EVENT* event, WOLF_EVENT_FLAG flags);
```

Polls the provided event to determine if its done.

### ```wolfAsync_EventQueue_Poll```

```
int wolfAsync_EventQueue_Poll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount);
```

Polls all events in the provided event queue. Optionally filters by context. Will return pointers to the done events.

### ```wolfAsync_EventInit```
```
int wolfAsync_EventInit(WOLF_EVENT* event, WOLF_EVENT_TYPE type, void* context);
```

Initialize an event structure with provided type and context. Sets the pending flag and the status code to WC_PENDING_E.

### ```wolfAsync_EventWait```
```
int wolfAsync_EventWait(WOLF_EVENT* event);
```

Waits for the provided event to complete.

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

