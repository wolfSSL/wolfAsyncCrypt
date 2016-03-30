# wolfAsyncCrypt

This respository contains the async.c and async.h files required for using Asynchronous Cryptography with the wolfSSL library.

* The async.c file goes into ./src/.
* The async.h file goes into ./wolfssl/.

This feature is enabled using:
`./configure --enable-asynccrypt` or `#define WOLFSSL_ASYNC_CRYPT`.

The async crypt simulator is enabled by default if the hardware does not support async crypto or it can be manually enabled using `#define WOLFSSL_ASYNC_CRYPT_TEST`.

## Design
A generic event system has been created using a `WOLF_EVENT` structure. If `HAVE_WOLF_EVENT` is defined then the `WOLFSSL` structure inclues a generic `WOLF_EVENT` for uses specific to that SSL connection.

The asyncronous crypto system is modeled after epoll. The implementation uses `wolfSSL_CTX_poll` to check if any async operations are complete.

## API's

### ```wolfSSL_async_pop```

```
int wolfSSL_async_pop(WOLFSSL* ssl, enum WOLF_EVENT_TYPE event_type);
```

This will check the ssl->event to see if the event type matches and the event is complete. If it is then the async return code is returned.

### ```wolfSSL_async_push```
```
int wolfSSL_async_push(WOLFSSL* ssl, enum WOLF_EVENT_TYPE event_type);
```

This populates the ssl->event with type and places it onto the ssl->ctx event queue.

### ```wolfSSL_async_poll ```
```
int wolfSSL_async_poll(WOLF_EVENT* event, unsigned char flags);
```

This function will physically try and check the status of the event in hardware. If the `WOLFSSL_ASYNC_CRYPT_TEST` define is set then it will use the async simulator.

### Poll flags:

* `WOLF_POLL_FLAG_CHECK_HW`: Flag permitting hardware check.
* `WOLF_POLL_FLAG_PEEK`: Flag to peek at the events only. If `events` arg is provided actual event data will be returned, otherwise the returned `eventCount` will be the total number of pending events.

### `wolfSSL_CTX_poll`
```
int wolfSSL_CTX_poll(WOLFSSL_CTX* ctx, WOLF_EVENT* events, int maxEvents,
                                 unsigned char flags, int* eventCount);
```

Poll function to perform async check for contact and return completed events. Events are returned in the `events` pointer (array) with `maxEvents` indicating how many `WOLF_EVENT` buffers are available. The number of actual events populated into `events` is returned in `eventCount`. If the `WOLF_POLL_FLAG_PEEK` flag is used the `events` arg is optional. If ommited the `eventCount` will be total count of items in queue.



### `wolfSSL_poll `
```
int wolfSSL_poll(WOLFSSL* ssl, WOLF_EVENT* events,
    int maxEvents, unsigned char flags, int* eventCount);
```

Same as `wolfSSL_CTX_poll`, but filters by `ssl` object.
