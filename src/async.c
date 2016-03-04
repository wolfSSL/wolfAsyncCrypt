/* async.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ASYNC_CRYPT
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/async.h>



#ifdef WOLFSSL_ASYNC_CRYPT_TEST
static int wolfSSL_async_crypt_test(WOLF_EVENT* event)
{
    int ret = 0;
    WOLFSSL* ssl = event->ssl;
    
    switch(ssl->asyncCryptTest.type) {
    #if defined(HAVE_ECC)
        case ASYNC_TEST_ECC_TMPKEY_GEN:
        {
            ret = EccMakeTempKey(ssl);
            break;
        }
        case ASYNC_TEST_ECC_SIGN:
        {
            ret = EccSign(ssl,
                ssl->asyncCryptTest.eccSign.in,
                ssl->asyncCryptTest.eccSign.inSz,
                ssl->asyncCryptTest.eccSign.out,
                ssl->asyncCryptTest.eccSign.outSz,
                ssl->asyncCryptTest.eccSign.key,
            #if defined(HAVE_PK_CALLBACKS)
                ssl->asyncCryptTest.eccSign.keyBuf,
                ssl->asyncCryptTest.eccSign.keySz,
                ssl->asyncCryptTest.ctx
            #else
                NULL, 0, NULL
            #endif
            );
            break;
        }
        case ASYNC_TEST_ECC_SHARED_SEC:
        {
            ret = EccSharedSecret(ssl,
                ssl->asyncCryptTest.eccSharedSec.private_key,
                ssl->asyncCryptTest.eccSharedSec.public_key,
                ssl->asyncCryptTest.eccSharedSec.out,
                ssl->asyncCryptTest.eccSharedSec.outLen);
            break;
        }
    #endif /* HAVE_ECC */
    #if !defined(NO_RSA)
        case ASYNC_TEST_RSA_SIGN:
        {
            ret = RsaSign(ssl,
                ssl->asyncCryptTest.rsaSign.in,
                ssl->asyncCryptTest.rsaSign.inSz,
                ssl->asyncCryptTest.rsaSign.out,
                ssl->asyncCryptTest.rsaSign.outSz,
                ssl->asyncCryptTest.rsaSign.key,
            #ifdef HAVE_PK_CALLBACKS
                ssl->asyncCryptTest.rsaSign.keyBuf,
                ssl->asyncCryptTest.rsaSign.keySz,
                ssl->asyncCryptTest.ctx
            #else
                NULL, 0, NULL
            #endif
            );
            break;
        }
        case ASYNC_TEST_RSA_DEC:
        {
            ret = RsaDec(ssl,
                ssl->asyncCryptTest.rsaDec.in,
                ssl->asyncCryptTest.rsaDec.inSz,
                ssl->asyncCryptTest.rsaDec.out,
                ssl->asyncCryptTest.rsaDec.outSz,
                ssl->asyncCryptTest.rsaDec.key,
            #ifdef HAVE_PK_CALLBACKS
                ssl->asyncCryptTest.rsaDec.keyBuf,
                ssl->asyncCryptTest.rsaDec.keySz,
                ssl->asyncCryptTest.ctx
            #else
                NULL, 0, NULL
            #endif
            );
            break;
        }
    #endif /* !NO_RSA */
    #if !defined(NO_DH)
        case ASYNC_TEST_DH_GEN:
        {
            ret = DhGenKeyPair(ssl,
                ssl->asyncCryptTest.dhGen.p,
                ssl->asyncCryptTest.dhGen.pSz,
                ssl->asyncCryptTest.dhGen.g,
                ssl->asyncCryptTest.dhGen.gSz,
                ssl->asyncCryptTest.dhGen.priv,
                ssl->asyncCryptTest.dhGen.privSz,
                ssl->asyncCryptTest.dhGen.pub,
                ssl->asyncCryptTest.dhGen.pubSz);
            break;
        }
        case ASYNC_TEST_DH_AGREE:
        {       
            ret = DhAgree(ssl,
                ssl->asyncCryptTest.dhAgree.p,
                ssl->asyncCryptTest.dhAgree.pSz,
                ssl->asyncCryptTest.dhAgree.g,
                ssl->asyncCryptTest.dhAgree.gSz,
                ssl->asyncCryptTest.dhAgree.priv,
                ssl->asyncCryptTest.dhAgree.privSz,
                ssl->asyncCryptTest.dhAgree.pub,
                ssl->asyncCryptTest.dhAgree.pubSz,
                ssl->asyncCryptTest.dhAgree.otherPub,
                ssl->asyncCryptTest.dhAgree.otherPubSz,
                ssl->asyncCryptTest.dhAgree.agree,
                ssl->asyncCryptTest.dhAgree.agreeSz);
            break;
        }
   #endif /* !NO_DH */
        default:
            WOLFSSL_MSG("Invalid async crypt test type!");
            ret = BAD_FUNC_ARG;
            break;
    };

    /* Reset test struct */
    XMEMSET(&ssl->asyncCryptTest, 0, sizeof(ssl->asyncCryptTest));

    /* Mark event as done for testing */
    event->done = 1;

    return ret;
}
#endif /* WOLFSSL_ASYNC_CRYPT_TEST */



int wolfSSL_async_pop(WOLFSSL* ssl, int event_type)
{
    int ret;

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl->event.type == event_type &&
        ssl->event.pending)
    {
        /* Trap the scenario where event is not done */
        if (!ssl->event.done) {
            return WC_PENDING_E;
        }

        /* Reset pending flag */
        ssl->event.pending = 0;

        /* Check async return code */
        ret = ssl->event.ret;
    }
    else {
        ret = ASYNC_NOT_PENDING;
    }

    return ret;
}

int wolfSSL_async_push(WOLFSSL* ssl, int event_type)
{
    int ret;

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Setup event and push to event queue */
    ret = wolfSSL_EventInit(ssl, event_type);
    if (ret == 0) {
        ret = wolfSSL_CTX_EventPush(ssl->ctx, &ssl->event);
    }

    return ret;
}

int wolfSSL_async_poll(WOLF_EVENT* event, unsigned char flags)
{
    int ret = SSL_ERROR_NONE;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Check hardware */
    if (flags & WOLF_POLL_FLAG_CHECK_HW) {
    #if defined(WOLFSSL_ASYNC_CRYPT_TEST)
        event->ret = wolfSSL_async_crypt_test(event);
    #else
        /* TODO: Implement real hardware checking */
        /* Note: event queue mutex is locked here, so make sure
            hardware doesn't try and lock event_queue */
        event->ret = 0;
        event->done = 1;
    #endif
    }

    return ret;
}

#endif /* WOLFSSL_ASYNC_CRYPT */
