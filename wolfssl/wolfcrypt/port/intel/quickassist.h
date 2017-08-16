/* quickassist.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _INTEL_QUICKASSIST_H_
#define _INTEL_QUICKASSIST_H_

#ifdef HAVE_INTEL_QA

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "cpa_cy_rsa.h"
#include "cpa_cy_ln.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ecdsa.h"
#include "cpa_cy_dh.h"
#include "cpa_cy_drbg.h"
#include "cpa_cy_nrbg.h"

/* User space utils */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef QAT_USE_POLLING_THREAD
    #include <pthread.h>
#endif
#ifdef QA_DEMO_MAIN
    #include <semaphore.h>
#endif


/* Tunable parameters */
#ifndef QAT_PROCESS_NAME
    #define QAT_PROCESS_NAME     "SSL"
#endif
#ifndef QAT_LIMIT_DEV_ACCESS
    #define QAT_LIMIT_DEV_ACCESS CPA_FALSE
#endif
#ifndef QAT_MAX_DEVICES
    #define QAT_MAX_DEVICES  (1)  /* maximum number of QAT cards */
#endif
#ifndef QAT_MAX_PENDING
    #define QAT_MAX_PENDING  (15) /* 120/num_threads = max num of concurrent ops */
#endif
#ifndef QAT_RETRY_LIMIT
    #define QAT_RETRY_LIMIT  (100)
#endif

/* TODO: Tune this value to get best performance */
#ifndef WC_ASYNC_THRESH_AES_CBC
    #define WC_ASYNC_THRESH_AES_CBC     128
#endif
#ifndef WC_ASYNC_THRESH_AES_GCM
    #define WC_ASYNC_THRESH_AES_GCM     128
#endif
#ifndef WC_ASYNC_THRESH_DES3_CBC
    #define WC_ASYNC_THRESH_DES3_CBC    128
#endif

/* Macros */
#define INVALID_STATUS -256


#if !defined(NO_SHA256) || defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384) ||\
    !defined(NO_HMAC) || !defined(NO_MD5) || defined(WOLFSSL_SHA224)
    #define QAT_ENABLE_HASH
#endif
#if !defined(NO_AES) || !defined(NO_DES3)
    #define QAT_ENABLE_CRYPTO
#endif
#if !defined(NO_RSA) || defined(HAVE_ECC) || !defined(NO_DH)
    #define QAT_ENABLE_PKI
#endif


/* Pre-declarations */
struct WC_ASYNC_DEV;
struct WC_BIGINT;
struct IntelQaDev;

#if defined(QAT_ENABLE_HASH) || defined(QAT_ENABLE_CRYPTO)
/* symmetric context */
typedef struct IntelQaSymCtx {
    CpaCySymOpData opData;
    CpaCySymSessionCtx symCtxSrc;
    CpaCySymSessionCtx symCtx;
    word32 symCtxSize;

    /* flags */
    word32 isOpen:1;
    word32 isCopy:1;
} IntelQaSymCtx;
#endif

typedef void (*IntelQaFreeFunc)(struct WC_ASYNC_DEV*);

/* QuickAssist device */
typedef struct IntelQaDev {
	CpaInstanceHandle handle;
    int devId;

    /* callback return info */
    int ret;
    byte* out;
    union {
        word32* outLenPtr;
        word32 outLen;
    };

    /* operations */
    IntelQaFreeFunc freeFunc;
    union {
    #ifndef NO_RSA
        struct {
            CpaCyRsaDecryptOpData opData;
            CpaCyRsaPrivateKey privateKey;
            CpaFlatBuffer outBuf;
        } rsa_priv;
        struct {
            CpaCyRsaEncryptOpData opData;
            CpaCyRsaPublicKey publicKey;
            CpaFlatBuffer outBuf;
        } rsa_pub;
        struct {
            CpaCyLnModExpOpData opData;
            CpaFlatBuffer target;
        } rsa_modexp;
    #endif
    #ifdef QAT_ENABLE_CRYPTO
        struct {
            IntelQaSymCtx ctx;
            CpaBufferList bufferList;
            CpaFlatBuffer flatBuffer;
            byte* authTag;
            word32 authTagSz;
        } cipher;
    #endif
#ifdef HAVE_ECC
    #ifdef HAVE_ECC_DHE
        struct {
            CpaCyEcdhPointMultiplyOpData opData;
            CpaFlatBuffer pXk;
            CpaFlatBuffer pYk;
        } ecc_ecdh;
    #endif
    #ifdef HAVE_ECC_SIGN
        struct {
            CpaCyEcdsaSignRSOpData opData;
            CpaFlatBuffer R;
            CpaFlatBuffer S;

            struct WC_BIGINT* pR;
            struct WC_BIGINT* pS;
        } ecc_sign;
    #endif
    #ifdef HAVE_ECC_VERIFY
        struct {
            CpaCyEcdsaVerifyOpData opData;
            int* stat;
        } ecc_verify;
    #endif
#endif
    #ifdef QAT_ENABLE_HASH
        struct {
            IntelQaSymCtx ctx;
            CpaBufferList* srcList;
            byte* tmpIn; /* tmp buffer to hold anything pending less than block size */
            word32 tmpInSz;
            word32 blockSize;
        } hash;
    #endif
    #ifndef NO_DH
        struct {
            CpaCyDhPhase1KeyGenOpData opData;
            CpaFlatBuffer pOut;
        } dh_gen;
        struct {
            CpaCyDhPhase2SecretKeyGenOpData opData;
            CpaFlatBuffer pOut;
        } dh_agree;
    #endif
        struct {
            CpaCyDrbgGenOpData opData;
            CpaCyDrbgSessionHandle handle;
            CpaFlatBuffer pOut;
        } drbg;
    } op;

#ifdef QAT_USE_POLLING_THREAD
    pthread_t pollingThread;
    byte pollingCy;
#endif
} IntelQaDev;


/* Interface */
WOLFSSL_LOCAL int IntelQaHardwareStart(const char* process_name, int limitDevAccess);
WOLFSSL_LOCAL void IntelQaHardwareStop(void);

WOLFSSL_LOCAL int IntelQaInit(void* threadId);
WOLFSSL_LOCAL void IntelQaDeInit(int);

WOLFSSL_LOCAL int IntelQaNumInstances(void);

WOLFSSL_LOCAL int IntelQaOpen(struct WC_ASYNC_DEV* dev, int devId);
WOLFSSL_LOCAL void IntelQaClose(struct WC_ASYNC_DEV* dev);

WOLFSSL_LOCAL int IntelQaDevCopy(struct WC_ASYNC_DEV* src, struct WC_ASYNC_DEV* dst);

WOLFSSL_LOCAL int IntelQaPoll(struct WC_ASYNC_DEV* dev);

WOLFSSL_LOCAL int IntelQaGetCyInstanceCount(void);

WOLFSSL_LOCAL void IntelQaOpFree(struct WC_ASYNC_DEV* dev);

#ifndef NO_RSA
    WOLFSSL_LOCAL int IntelQaRsaPrivate(struct WC_ASYNC_DEV* dev,
                            const byte* in, word32 inLen,
                            struct WC_BIGINT* d, struct WC_BIGINT* n,
                            byte* out, word32* outLen);
    WOLFSSL_LOCAL int IntelQaRsaCrtPrivate(struct WC_ASYNC_DEV* dev,
                            const byte* in, word32 inLen,
                            struct WC_BIGINT* p, struct WC_BIGINT* q,
                            struct WC_BIGINT* dP, struct WC_BIGINT* dQ,
                            struct WC_BIGINT* qInv,
                            byte* out, word32* outLen);
    WOLFSSL_LOCAL int IntelQaRsaPublic(struct WC_ASYNC_DEV* dev,
                            const byte* in, word32 inLen,
                            struct WC_BIGINT* e, struct WC_BIGINT* n,
                            byte* out, word32* outLen);
    WOLFSSL_LOCAL int IntelQaRsaExptMod(struct WC_ASYNC_DEV* dev,
                            const byte* in, word32 inLen,
                            struct WC_BIGINT* e, struct WC_BIGINT* n,
                            byte* out, word32* outLen);
#endif /* !NO_RSA */

#ifndef NO_AES
    #ifdef HAVE_AES_CBC
        WOLFSSL_LOCAL int IntelQaSymAesCbcEncrypt(struct WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz);
    #ifdef HAVE_AES_DECRYPT
        WOLFSSL_LOCAL int IntelQaSymAesCbcDecrypt(struct WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz);
    #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AES_CBC */

    #ifdef HAVE_AESGCM
        WOLFSSL_LOCAL int IntelQaSymAesGcmEncrypt(struct WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz,
            byte* authTag, word32 authTagSz,
            const byte* authIn, word32 authInSz);
    #ifdef HAVE_AES_DECRYPT
        WOLFSSL_LOCAL int IntelQaSymAesGcmDecrypt(struct WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz,
            const byte* key, word32 keySz,
            const byte* iv, word32 ivSz,
            const byte* authTag, word32 authTagSz,
            const byte* authIn, word32 authInSz);
    #endif /* HAVE_AES_DECRYPT */
    #endif /* HAVE_AESGCM */
#endif /* !NO_AES */

#ifndef NO_DES3
    WOLFSSL_LOCAL int IntelQaSymDes3CbcEncrypt(struct WC_ASYNC_DEV* dev,
                byte* out, const byte* in, word32 sz,
                const byte* key, word32 keySz,
                const byte* iv, word32 ivSz);
    WOLFSSL_LOCAL int IntelQaSymDes3CbcDecrypt(struct WC_ASYNC_DEV* dev,
                byte* out, const byte* in, word32 sz,
                const byte* key, word32 keySz,
                const byte* iv, word32 ivSz);
#endif /*! NO_DES3 */

#ifdef WOLFSSL_SHA512
    WOLFSSL_LOCAL int IntelQaSymSha512(struct WC_ASYNC_DEV* dev, byte* out,
        const byte* in, word32 sz);

    #ifdef WOLFSSL_SHA384
        WOLFSSL_LOCAL int IntelQaSymSha384(struct WC_ASYNC_DEV* dev,
            byte* out, const byte* in, word32 sz);
    #endif
#endif

#ifndef NO_SHA256
    WOLFSSL_LOCAL int IntelQaSymSha256(struct WC_ASYNC_DEV* dev, byte* out,
        const byte* in, word32 sz);
    #ifdef WOLFSSL_SHA224
        WOLFSSL_LOCAL int IntelQaSymSha224(struct WC_ASYNC_DEV* dev, byte* out,
        const byte* in, word32 sz);
    #endif
#endif /* !NO_SHA256 */

#ifndef NO_SHA
    WOLFSSL_LOCAL int IntelQaSymSha(struct WC_ASYNC_DEV* dev, byte* out,
        const byte* in, word32 sz);
#endif /* !NO_SHA */

#ifndef NO_MD5
    WOLFSSL_LOCAL int IntelQaSymMd5(struct WC_ASYNC_DEV* dev, byte* out,
        const byte* in, word32 sz);
#endif /* !NO_MD5 */

#ifdef HAVE_ECC
    #ifdef HAVE_ECC_DHE
        WOLFSSL_LOCAL int IntelQaEcdh(struct WC_ASYNC_DEV* dev,
            struct WC_BIGINT* k, struct WC_BIGINT* xG,
            struct WC_BIGINT* yG, byte* out, word32* outlen,
            struct WC_BIGINT* a, struct WC_BIGINT* b,
            struct WC_BIGINT* q, word32 cofactor);
    #endif /* HAVE_ECC_DHE */
    #ifdef HAVE_ECC_SIGN
        WOLFSSL_LOCAL int IntelQaEcdsaSign(struct WC_ASYNC_DEV* dev,
            struct WC_BIGINT* m, struct WC_BIGINT* d,
            struct WC_BIGINT* k,
            struct WC_BIGINT* r, struct WC_BIGINT* s,
            struct WC_BIGINT* a, struct WC_BIGINT* b,
            struct WC_BIGINT* q, struct WC_BIGINT* n,
            struct WC_BIGINT* xg, struct WC_BIGINT* yg);
    #endif /* HAVE_ECC_SIGN */
    #ifdef HAVE_ECC_VERIFY
        WOLFSSL_LOCAL int IntelQaEcdsaVerify(struct WC_ASYNC_DEV* dev,
            struct WC_BIGINT* m, struct WC_BIGINT* xp,
            struct WC_BIGINT* yp, struct WC_BIGINT* r,
            struct WC_BIGINT* s, struct WC_BIGINT* a,
            struct WC_BIGINT* b, struct WC_BIGINT* q,
            struct WC_BIGINT* n, struct WC_BIGINT* xg,
            struct WC_BIGINT* yg, int* stat);
    #endif /* HAVE_ECC_VERIFY */
#endif /* HAVE_ECC */

#ifndef NO_DH
    WOLFSSL_LOCAL int IntelQaDhKeyGen(struct WC_ASYNC_DEV* dev,
        struct WC_BIGINT* p, struct WC_BIGINT* g, struct WC_BIGINT* x,
        byte* pub, word32* pubSz);


    WOLFSSL_LOCAL int IntelQaDhAgree(struct WC_ASYNC_DEV* dev,
        struct WC_BIGINT* p,
        byte* agree, word32* agreeSz,
        const byte* priv, word32 privSz,
        const byte* otherPub, word32 pubSz);
#endif /* !NO_DH */

#ifndef NO_HMAC
    WOLFSSL_LOCAL int IntelQaHmac(struct WC_ASYNC_DEV* dev,
        int macType, byte* keyRaw, word16 keyLen,
        byte* out, const byte* in, word32 sz);
#endif /* !NO_HMAC */

WOLFSSL_LOCAL int IntelQaDrbg(struct WC_ASYNC_DEV* dev, byte* rngBuf, word32 rngSz);
WOLFSSL_LOCAL int IntelQaNrbg(CpaFlatBuffer* pBuffer, Cpa32U length);

#endif /* HAVE_INTEL_QA */

#endif /* _INTEL_QUICKASSIST_H_ */
