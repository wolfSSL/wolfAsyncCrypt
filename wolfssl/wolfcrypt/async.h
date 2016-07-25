/* async.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFSSL_ASYNC_H
#define WOLFSSL_ASYNC_H

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_ASYNC_CRYPT

#include <wolfssl/wolfcrypt/wolfevent.h>
#ifdef HAVE_CAVIUM
    #include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#endif


#ifndef WOLFCRYPT_ONLY
    /* this strucutre is used for caching TLS state on WC_PENDING_E */
    typedef struct AsyncCryptSSLState {
        byte*           output;        /* This is a pointer to outputBuffer, 
                                          no need to free */
        byte*           data;          /* General Purpose data buffer */
        word32          sendSz;
        word32          sigSz;
        word32          idx;
        word32          length;
        int             hashAlgo;
        byte            sigAlgo;
    } AsyncCryptSSLState;
#endif /* !WOLFCRYPT_ONLY */

/* state tracking for async crypto */
typedef struct AsyncCryptState {
    int     state;
} AsyncCryptState;


/* Asyncronous Crypt Tests */
#ifdef WOLFSSL_ASYNC_CRYPT_TEST
    enum AsyncCryptTestType {
        ASYNC_TEST_NONE,
    #ifdef ATOMIC_USER
        ASYNC_TEST_MAC_ENC,
        ASYNC_TEST_DEC_VERIFY,
    #endif /* ATOMIC_USER */
    #ifdef HAVE_ECC
        ASYNC_TEST_ECC_MAKE,
        ASYNC_TEST_ECC_SIGN,
        ASYNC_TEST_ECC_VERIFY,
        ASYNC_TEST_ECC_SHARED_SEC,
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        ASYNC_TEST_RSA_FUNC,
        ASYNC_TEST_RSA_SIGN,
        ASYNC_TEST_RSA_VERIFY,
        ASYNC_TEST_RSA_VERIFYINLINE,
        ASYNC_TEST_RSA_ENC,
        ASYNC_TEST_RSA_DEC,
        ASYNC_TEST_RSA_DECINLINE,
    #endif /* !NO_RSA */
    #if !defined(NO_DH)
        ASYNC_TEST_DH_GEN,
        ASYNC_TEST_DH_AGREE,
    #endif /* !NO_DH */
    };

#ifdef ATOMIC_USER
    struct AsyncCryptTestMacEncrypt {
        byte* macOut;
        const byte* macIn;
        word32 macInSz;
        int macContent;
        int macVerify;
        byte* encOut;
        const byte* encIn;
        word32 encSz;
    };
    struct AsyncCryptTestDecryptVerify {
        byte* decOut;
        const byte* decIn;
        word32 decSz;
        int macContent;
        int macVerify;
        word32* padSz;
    };
#endif /* ATOMIC_USER */
#ifdef HAVE_ECC
    struct AsyncCryptTestEccMake {
        void* rng; /* WC_RNG */
        void* key; /* ecc_key */
        int curve_id;
        int size;
    };
    struct AsyncCryptTestEccSign {
        const byte* in;
        word32 inSz;
        byte* out;
        word32* outSz;
        void* rng; /* WC_RNG */
        void* key; /* ecc_key */
    };
    struct AsyncCryptTestEccVerify {
        const byte* in;
        word32 inSz;
        const byte* out;
        word32 outSz;
        int* stat;
        void* key; /* ecc_key */
    };
    struct AsyncCryptTestEccSharedSec {
        void* private_key; /* ecc_key */
        void* public_key; /* ecc_key */
        byte* out;
        word32* outLen;
    };
#endif /* HAVE_ECC */
#ifndef NO_RSA
    struct AsyncCryptTestRsaFunc {
        const byte* in;
        word32 inSz;
        byte* out;
        word32* outSz;
        int type;
        void* key; /* RsaKey */
        void* rng;
    };
#endif /* !NO_RSA */


    typedef struct AsyncCryptTestDev {
        void* ctx;
        union {
    #ifdef ATOMIC_USER
            struct AsyncCryptTestMacEncrypt macEncrypt;
            struct AsyncCryptTestDecryptVerify decryptVerify;
    #endif /* ATOMIC_USER */
    #ifdef HAVE_ECC
            struct AsyncCryptTestEccMake eccMake;
            struct AsyncCryptTestEccSign eccSign;
            struct AsyncCryptTestEccVerify eccVerify;
            struct AsyncCryptTestEccSharedSec eccSharedSec;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
            struct AsyncCryptTestRsaFunc rsaFunc;
    #endif /* !NO_RSA */
        }; /* union */
        byte type; /* enum AsyncCryptTestType */
    } AsyncCryptTestDev;
#endif /* WOLFSSL_ASYNC_CRYPT_TEST */

/* determine maximum async pending requests */
#ifdef HAVE_CAVIUM
    #define WOLF_ASYNC_MAX_PENDING CAVIUM_MAX_PENDING
#elif defined(HAVE_INTEL_QA)
    /* TODO: Add max pending for Intel QuickAssist */
#else
    #define WOLF_ASYNC_MAX_PENDING      1

    /* Use this to introduce extra delay in test where count % mod has remainder */
    /* Must be less than WOLF_ASYNC_MAX_PENDING */
    //#define WOLF_ASYNC_TEST_SKIP_MOD    10
#endif


/* async marker values */
#define WOLFSSL_ASYNC_MARKER_ARC4   0xBEEF0001
#define WOLFSSL_ASYNC_MARKER_AES    0xBEEF0002
#define WOLFSSL_ASYNC_MARKER_3DES   0xBEEF0003
#define WOLFSSL_ASYNC_MARKER_RNG    0xBEEF0004
#define WOLFSSL_ASYNC_MARKER_HMAC   0xBEEF0005
#define WOLFSSL_ASYNC_MARKER_RSA    0xBEEF0006
#define WOLFSSL_ASYNC_MARKER_ECC    0xBEEF0007

/* async device handle */
#ifdef HAVE_CAVIUM
    typedef CspHandle   AsyncDevHandle;
#else
    typedef int         AsyncDevHandle;
#endif

/* async device */
typedef struct AsyncCryptDev {
    word32 marker;  /* async marker */
#ifdef HAVE_CAVIUM
    /* context for Cavium driver */
    CaviumNitroxDev dev;
#else
    /* context for test driver */
    AsyncCryptTestDev dev;
#endif
} AsyncCryptDev;



WOLFSSL_API int wolfAsync_DevOpen(int *devId);
WOLFSSL_API int wolfAsync_DevCtxInit(AsyncCryptDev* asyncDev, int marker, int devId);
WOLFSSL_API void wolfAsync_DevCtxFree(AsyncCryptDev* asyncDev);
WOLFSSL_API void wolfAsync_DevClose(int *devId);

WOLFSSL_API int wolfAsync_EventInit(WOLF_EVENT* event, enum WOLF_EVENT_TYPE type, void* context);
WOLFSSL_API int wolfAsync_EventWait(WOLF_EVENT* event);
WOLFSSL_API int wolfAsync_EventPoll(WOLF_EVENT* event, WOLF_EVENT_FLAG flags);
WOLFSSL_API int wolfAsync_EventPop(WOLF_EVENT* event, enum WOLF_EVENT_TYPE event_type);
WOLFSSL_API int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event);
WOLFSSL_API int wolfAsync_EventQueuePoll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount);

#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_ASYNC_H */
