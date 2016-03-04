# wolfAsyncCrypt

This respository contains the async.c and async.h files required for using Asynchronous Cryptography with the wolfSSL library.

* The async.c file goes into ./src/.
* The async.h file goes into ./wolfssl/.

This feature is enabled using:
`./configure --enable-asynccrypt` or `#define WOLFSSL_ASYNC_CRYPT`.

The async crypt simulator is enabled by default if the hardware does not support async crypto or it can be manually enabled using `#define WOLFSSL_ASYNC_CRYPT_TEST`.
