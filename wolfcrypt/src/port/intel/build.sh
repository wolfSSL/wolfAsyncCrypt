#!/bin/bash

WOLF_ROOT="../../../.."
QAT_ROOT="$WOLF_ROOT/../QAT1.7"
QAT_LIB=
LDFLAGS=

# QAT v1.6
#QAT_ROOT="$WOLF_ROOT/../QAT1.6"
#QAT_LIB+="-lrt -losal $QAT_ROOT/build/libicp_qa_al_s.so"

CFLAGS="-I$WOLF_ROOT -I$WOLF_ROOT/wolfssl -I$QAT_ROOT/quickassist/include -I$QAT_ROOT/quickassist/include/lac \
    -I$QAT_ROOT/quickassist/utilities/osal/include -I$QAT_ROOT/quickassist/utilities/osal/src/linux/user_space/include \
    -I$QAT_ROOT/quickassist/lookaside/access_layer/include -I$QAT_ROOT/quickassist/lookaside/access_layer/src/common/include \
    -I$WOLF_ROOT/wolfssl/wolfcrypt/port/intel -I$QAT_ROOT/quickassist/utilities/libusdm_drv"

LDFLAGS+="-L/usr/Lib -lpthread -lcrypto -lm -lpthread"
QAT_LIB="-lqat_s -lusdm_drv_s"
OPTIONS="-Wall -O0 -DHAVE_INTEL_QA -DOPENSSL_EXTRA -DQAT_DEMO_MAIN -DWOLFSSL_ASYNC_CRYPT -DHAVE_WOLF_EVENT -DUSE_FAST_MATH \
    -DTFM_TIMING_RESISTANT -DECC_TIMING_RESISTANT -DWC_RSA_BLINDING -DWOLFSSL_SHA384 -DWOLFSSL_SHA512 -DHAVE_AESGCM \
    -DHAVE_ECC -DHAVE_ECC_DHE -DHAVE_WOLF_BIGINT -DUSER_SPACE -DDO_CRYPTO -D_GNU_SOURCE"
DEBUG="-g -DDEBUG -DDEBUG_WOLFSSL -DQAT_DEBUG"

gcc $CFLAGS $OPTIONS $DEBUG $LDFLAGS $QAT_LIB quickassist.c quickassist_mem.c $WOLF_ROOT/wolfcrypt/src/md5.c $WOLF_ROOT/src/internal.c $WOLF_ROOT/src/ssl.c \
    $WOLF_ROOT/wolfcrypt/src/sha.c $WOLF_ROOT/wolfcrypt/src/sha256.c $WOLF_ROOT/wolfcrypt/src/async.c $WOLF_ROOT/wolfcrypt/src/wolfevent.c $WOLF_ROOT/wolfcrypt/src/wc_port.c $WOLF_ROOT/wolfcrypt/src/random.c $WOLF_ROOT/wolfcrypt/src/tfm.c \
    $WOLF_ROOT/wolfcrypt/src/hmac.c $WOLF_ROOT/wolfcrypt/src/memory.c $WOLF_ROOT/wolfcrypt/src/aes.c $WOLF_ROOT/wolfcrypt/src/des3.c $WOLF_ROOT/wolfcrypt/src/dh.c $WOLF_ROOT/wolfcrypt/src/dsa.c $WOLF_ROOT/wolfcrypt/src/ecc.c \
    $WOLF_ROOT/wolfcrypt/src/coding.c $WOLF_ROOT/wolfcrypt/src/asn.c $WOLF_ROOT/wolfcrypt/src/hash.c $WOLF_ROOT/src/tls.c $WOLF_ROOT/wolfcrypt/src/pwdbased.c $WOLF_ROOT/wolfcrypt/src/arc4.c $WOLF_ROOT/wolfcrypt/src/rsa.c \
    $WOLF_ROOT/src/keys.c $WOLF_ROOT/wolfcrypt/src/sha512.c $WOLF_ROOT/src/wolfio.c $WOLF_ROOT/wolfcrypt/src/wc_encrypt.c $WOLF_ROOT/wolfcrypt/src/md4.c $WOLF_ROOT/wolfcrypt/src/logging.c $WOLF_ROOT/wolfcrypt/src/error.c $WOLF_ROOT/wolfcrypt/src/wolfmath.c \
    $WOLF_ROOT/wolfcrypt/src/pkcs12.c \
    -o qat_test
