/* async.h
 *
 * Copyright (C) 2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef WOLFSSL_ASYNC_H
#define WOLFSSL_ASYNC_H

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_ASYNC_CRYPT

typedef struct AsyncCrypt {
    byte*           output;        /* This is a pointer to outputBuffer, 
                                      no need to free */
    word32          sendSz;    
    word32          sigSz;
    word32          idx;
    word32          length;
} AsyncCrypt;


WOLFSSL_LOCAL int wolfSSL_async_pop(WOLFSSL* ssl, int event_type);
WOLFSSL_LOCAL int wolfSSL_async_push(WOLFSSL* ssl, int event_type);
WOLFSSL_LOCAL int wolfSSL_async_poll(WOLF_EVENT* event, unsigned char flags);


/* Asyncronous Crypt Tests */
#ifdef WOLFSSL_ASYNC_CRYPT_TEST
    enum AsyncCryptTestType {
        ASYNC_TEST_NONE,
    #ifdef ATOMIC_USER
        ASYNC_TEST_MAC_ENC,
        ASYNC_TEST_DEC_VERIFY,
    #endif /* ATOMIC_USER */
    #ifdef HAVE_ECC
        ASYNC_TEST_ECC_TMPKEY_GEN,
        ASYNC_TEST_ECC_SIGN,
        ASYNC_TEST_ECC_VERIFY,
        ASYNC_TEST_ECC_SHARED_SEC,
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        ASYNC_TEST_RSA_SIGN,
        ASYNC_TEST_RSA_VERIFY,
        ASYNC_TEST_RSA_ENC,
        ASYNC_TEST_RSA_DEC,
    #endif /* !NO_RSA */
    #if !defined(NO_DH)
        ASYNC_TEST_DH_GEN,
        ASYNC_TEST_DH_AGREE,
    #endif /* !NO_DH */
    };

    typedef struct AsyncCryptTests {
        void* ctx;
        union {
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
            } macEncrypt;
            struct AsyncCryptTestDecryptVerify {
                byte* decOut;
                const byte* decIn;
                word32 decSz;
                int macContent;
                int macVerify;
                word32* padSz;
            } decryptVerify;
    #endif /* ATOMIC_USER */
    #ifdef HAVE_ECC
            struct AsyncCryptTestEccSign {
                const byte* in;
                word32 inSz;
                byte* out;
                word32* outSz;
                const byte* keyBuf;
                word32 keySz;
                ecc_key* key;
            } eccSign;
            struct AsyncCryptTestEccVerify {
                const byte* sig;
                word32 sigSz;
                const byte* hash;
                word32 hashSz;
                const byte* key;
                word32 keySz;
                int* result;
            } eccVerify;
            struct AsyncCryptTestEccSharedSec {
                ecc_key* private_key;
                ecc_key* public_key;
                byte* out;
                word32* outLen;
            } eccSharedSec;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
            struct AsyncCryptTestRsaSign {
                const byte* in;
                word32 inSz;
                byte* out;
                word32* outSz;
                const byte* keyBuf;
                word32 keySz;
                RsaKey* key;
            } rsaSign;
            struct AsyncCryptTestRsaVerify {
                byte* sig;
                word32 sigSz;
                byte** out;
                const byte* keyBuf;
                word32 keySz;
                RsaKey* key;
            } rsaVerify;
            struct AsyncCryptTestRsaEnc {
                const byte* in;
                word32 inSz;
                byte* out;
                word32* outSz;
                const byte* keyBuf;
                word32 keySz;
                RsaKey* key;
            } rsaEnc;
            struct AsyncCryptTestRsaDec {
                byte* in;
                word32 inSz;
                byte** out;
                word32* outSz;
                const byte* keyBuf;
                word32 keySz;
                RsaKey* key;
            } rsaDec;
    #endif /* !NO_RSA */
    #if !defined(NO_DH)
            struct AsyncCryptTestDhGen {
                byte* p;
                word32 pSz;
                byte* g;
                word32 gSz;
                byte* priv;
                word32* privSz;
                byte* pub;
                word32* pubSz;
            } dhGen;
            struct AsyncCryptTestDhAgree {
                byte* p;
                word32 pSz;
                byte* g;
                word32 gSz;
                byte* priv;
                word32* privSz;
                byte* pub;
                word32* pubSz;
                const byte* otherPub;
                word32 otherPubSz;
                byte* agree;
                word32* agreeSz;
            } dhAgree;
    #endif /* !NO_DH */
        }; /* union */
        byte type; /* enum AsyncCryptTestType */
    } AsyncCryptTests;
#endif /* WOLFSSL_ASYNC_CRYPT_TEST */

#endif /* WOLFSSL_ASYNC_CRYPT */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_ASYNC_H */
