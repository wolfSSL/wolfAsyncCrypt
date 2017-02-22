#!/bin/bash

WOLF_ROOT="../../../.."
QAT_ROOT="$WOLF_ROOT/../QAT1.6"

CFLAGS="-I$WOLF_ROOT -I$QAT_ROOT/quickassist/include -I$QAT_ROOT/quickassist/include/lac -I$QAT_ROOT/quickassist/include/dc -I$QAT_ROOT/quickassist/utilities/osal/include -I$QAT_ROOT/quickassist/utilities/osal/src/linux/user_space/include
    -I$QAT_ROOT/quickassist/lookaside/access_layer/include \
    -I$QAT_ROOT/quickassist/lookaside/access_layer/src/common/include -I$WOLF_ROOT/wolfssl -I$WOLF_ROOT/wolfssl/wolfcrypt/port/intel"
LDFLAGS="-L/usr/Lib -lpthread -lcrypto -lm -lpthread -lrt"
OPTIONS="-Wall -O0 -DHAVE_INTEL_QA -DOPENSSL_EXTRA -DQAT_DEMO_MAIN -DWOLFSSL_ASYNC_CRYPT -DHAVE_WOLF_EVENT -DUSE_FAST_MATH -DWOLFSSL_SHA384 -DWOLFSSL_SHA512 -DHAVE_AESGCM -DUSER_SPACE -DDO_CRYPTO -D_GNU_SOURCE -DHAVE_ECC -DHAVE_ECC_DHE -DHAVE_WOLF_BIGINT"
DEBUG="-g -DDEBUG -DDEBUG_WOLFSSL"

gcc $CFLAGS $OPTIONS $DEBUG $LDFLAGS quickassist.c quickassist_mem.c $QAT_ROOT/build/libicp_qa_al_s.so $WOLF_ROOT/wolfcrypt/src/md5.c $WOLF_ROOT/src/internal.c $WOLF_ROOT/src/ssl.c \
    $WOLF_ROOT/wolfcrypt/src/sha.c $WOLF_ROOT/wolfcrypt/src/sha256.c $WOLF_ROOT/wolfcrypt/src/async.c $WOLF_ROOT/wolfcrypt/src/wolfevent.c $WOLF_ROOT/wolfcrypt/src/wc_port.c $WOLF_ROOT/wolfcrypt/src/random.c $WOLF_ROOT/wolfcrypt/src/tfm.c \
    $WOLF_ROOT/wolfcrypt/src/hmac.c $WOLF_ROOT/wolfcrypt/src/memory.c $WOLF_ROOT/wolfcrypt/src/aes.c $WOLF_ROOT/wolfcrypt/src/des3.c $WOLF_ROOT/wolfcrypt/src/dh.c $WOLF_ROOT/wolfcrypt/src/dsa.c $WOLF_ROOT/wolfcrypt/src/ecc.c \
    $WOLF_ROOT/wolfcrypt/src/coding.c $WOLF_ROOT/wolfcrypt/src/asn.c $WOLF_ROOT/wolfcrypt/src/hash.c $WOLF_ROOT/src/tls.c $WOLF_ROOT/wolfcrypt/src/pwdbased.c $WOLF_ROOT/wolfcrypt/src/arc4.c $WOLF_ROOT/wolfcrypt/src/rsa.c \
    $WOLF_ROOT/src/keys.c $WOLF_ROOT/wolfcrypt/src/sha512.c $WOLF_ROOT/src/io.c $WOLF_ROOT/wolfcrypt/src/wc_encrypt.c $WOLF_ROOT/wolfcrypt/src/md4.c $WOLF_ROOT/wolfcrypt/src/logging.c $WOLF_ROOT/wolfcrypt/src/error.c $WOLF_ROOT/wolfcrypt/src/wolfmath.c \
    $WOLF_ROOT/wolfcrypt/src/pkcs12.c \
    -o qat_test
