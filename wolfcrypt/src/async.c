/* async.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ASYNC_CRYPT
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/async.h>


#if defined(WOLFSSL_ASYNC_CRYPT_TEST)

/* Allow way to have async test code included, and disabled at run-time */
static int wolfAsyncTestDisabled = 0; /* default off */


static int wolfAsync_crypt_test(WOLF_EVENT* event)
{
    int ret = 0;
    AsyncCryptDev* asyncDev = (AsyncCryptDev*)event->context;
    AsyncCryptTestDev* testDev;

    if (asyncDev == NULL) {
        return BAD_FUNC_ARG;
    }
    testDev = &asyncDev->dev;

    switch(testDev->type) {
    #if defined(HAVE_ECC)
        case ASYNC_TEST_ECC_MAKE:
        {
            ret = wc_ecc_make_key_ex(
                (WC_RNG*)testDev->eccMake.rng,
                testDev->eccMake.size,
                (ecc_key*)testDev->eccMake.key,
                testDev->eccMake.curve_id
            );
            break;
        }
        case ASYNC_TEST_ECC_SIGN:
        {
            ret = wc_ecc_sign_hash(
                testDev->eccSign.in,
                testDev->eccSign.inSz,
                testDev->eccSign.out,
                testDev->eccSign.outSz,
                (WC_RNG*)testDev->eccSign.rng,
                (ecc_key*)testDev->eccSign.key
            );
            break;
        }
        case ASYNC_TEST_ECC_VERIFY:
        {
            ret = wc_ecc_verify_hash(
                testDev->eccVerify.in,
                testDev->eccVerify.inSz,
                testDev->eccVerify.out,
                testDev->eccVerify.outSz,
                testDev->eccVerify.stat,
                (ecc_key*)testDev->eccVerify.key
            );
            break;
        }
        case ASYNC_TEST_ECC_SHARED_SEC:
        {
            ret = wc_ecc_shared_secret(
                (ecc_key*)testDev->eccSharedSec.private_key,
                (ecc_key*)testDev->eccSharedSec.public_key,
                testDev->eccSharedSec.out,
                testDev->eccSharedSec.outLen
            );
            break;
        }
    #endif /* HAVE_ECC */
    #if !defined(NO_RSA)
        case ASYNC_TEST_RSA_FUNC:
        {
            ret = wc_RsaFunction(
                testDev->rsaFunc.in,
                testDev->rsaFunc.inSz,
                testDev->rsaFunc.out,
                testDev->rsaFunc.outSz,
                testDev->rsaFunc.type,
                (RsaKey*)testDev->rsaFunc.key,
                testDev->rsaFunc.rng
            );
            break;
        }
    #endif /* !NO_RSA */
        default:
            WOLFSSL_MSG("Invalid async crypt test type!");
            ret = BAD_FUNC_ARG;
            break;
    };

    /* Reset test struct */
    //XMEMSET(testDev, 0, sizeof(AsyncCryptTestDev));
    testDev->type = ASYNC_TEST_NONE;

    /* Mark event as done for testing */
    event->done = 1;
    event->pending = 0;

    return ret;
}
#endif /* WOLFSSL_ASYNC_CRYPT_TEST && !WOLFCRYPT_ONLY */

int wolfAsync_DevOpen(int *devId)
{
    int ret = BAD_FUNC_ARG;

    if (devId) {
    #ifdef HAVE_CAVIUM
        *devId = NitroxOpenDevice(CAVIUM_DIRECT, CAVIUM_DEV_ID);
        if (*devId >= 0) {
            ret = 0;
        }
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add device open for Intel QuickAssist */
        ret = 0;
    #elif defined(WOLFSSL_ASYNC_CRYPT_TEST)
        if (!wolfAsyncTestDisabled) {
            /* For test wse any value != INVALID_DEVID */
            *devId = 0;
        }
        ret = 0;
    #endif
    }

    return ret;
}

void wolfAsync_DevClose(int *devId)
{
    if (devId && *devId != INVALID_DEVID) {
    #ifdef HAVE_CAVIUM
        NitroxCloseDevice(*devId);
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add device close for Intel QuickAssist */
    #endif
        *devId = INVALID_DEVID;
    }
}

int wolfAsync_DevCtxInit(AsyncCryptDev* asyncDev, int marker, int devId)
{
    int ret = BAD_FUNC_ARG;

    if (asyncDev == NULL) {
        return ret;
    }

    (void)devId;

    XMEMSET(asyncDev, 0, sizeof(AsyncCryptDev));
    asyncDev->marker = marker;

#ifdef HAVE_CAVIUM
    ret = NitroxAllocContext(&asyncDev->dev, devId, CONTEXT_SSL);
#elif defined(HAVE_INTEL_QA)
    /* TODO: Add device context open for Intel QuickAssist */
#else
    ret = 0;
#endif

    return ret;
}

void wolfAsync_DevCtxFree(AsyncCryptDev* asyncDev)
{
    if (asyncDev && asyncDev->marker != 0) {
    #ifdef HAVE_CAVIUM
        NitroxFreeContext(&asyncDev->dev);
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add device context free for Intel QuickAssist */
    #endif
        asyncDev->marker = 0;
    }
}



int wolfAsync_EventPop(WOLF_EVENT* event, enum WOLF_EVENT_TYPE event_type)
{
    int ret;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    if (event->type == event_type || 
            (event_type == WOLF_EVENT_TYPE_ASYNC_ANY &&
                event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
                event->type <= WOLF_EVENT_TYPE_ASYNC_LAST))
    {
        /* Trap the scenario where event is not done */
        if (!event->done) {
            return WC_PENDING_E;
        }

        /* Reset pending flag */
        event->pending = 0;

        /* Check async return code */
        ret = event->ret;
    }
    else {
        ret = WC_NOT_PENDING_E;
    }

    return ret;
}

int wolfAsync_EventQueuePush(WOLF_EVENT_QUEUE* queue, WOLF_EVENT* event)
{
    if (queue == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Setup event and push to event queue */
    return wolfEventQueue_Push(queue, event);
}

int wolfAsync_EventPoll(WOLF_EVENT* event, WOLF_EVENT_FLAG flags)
{
    int ret = 0;

    (void)flags;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    if (flags & WOLF_POLL_FLAG_CHECK_HW) {
    #if defined(HAVE_CAVIUM)
        /* Note: event queue mutex is locked here, so make sure
        hardware doesn't try and lock event_queue */

        AsyncCryptDev* asyncDev = (AsyncCryptDev*)event->context;
        event->ret = NitroxCheckRequest(asyncDev->dev.devId, event->reqId);

        /* If not pending then mark as done */
        if (event->ret != WC_PENDING_E) {
            event->done = 1;
            event->pending = 0;
        }
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add hardware polling for Intel QuickAssist */
    #else
        event->ret = wolfAsync_crypt_test(event);
    #endif
    }

    return ret;
}


#ifdef HAVE_CAVIUM
static int wolfAsync_CheckMultiReqBuf(AsyncCryptDev* asyncDev,
    WOLF_EVENT_QUEUE* queue, void* context_filter,
    CspMultiRequestStatusBuffer* multi_req)
{
    WOLF_EVENT* event;
    int ret = 0, i;

    if (asyncDev == NULL || queue == NULL || multi_req == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Perform multi hardware poll */
    ret = NitroxCheckRequests(asyncDev->dev.devId, multi_req);
    if (ret != 0) {
        return ret;
    }

    /* Itterate event queue */
    for (event = queue->head; event != NULL; event = event->next)
    {
        /* optional filter based on context */
        if (context_filter == NULL || event->context == context_filter) {
            if (event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
                event->type <= WOLF_EVENT_TYPE_ASYNC_LAST)
            {
                /* find request */
                for (i = 0; i < CAVIUM_MAX_POLL; i++) {
                    if (event->reqId > 0 && event->reqId == multi_req->req[i].request_id) {
                        event->ret = NitroxTranslateResponseCode(multi_req->req[i].status);

                        /* If not pending then mark as done */
                        if (event->ret != WC_PENDING_E) {
                            event->done = 1;
                            event->pending = 0;
                            event->reqId = 0;
                        }
                        break;
                    }
                }
            }
        }
    }

    /* reset multi request buffer */
    XMEMSET(multi_req, 0, sizeof(CspMultiRequestStatusBuffer));

    return ret;
}
#endif

int wolfAsync_EventQueuePoll(WOLF_EVENT_QUEUE* queue, void* context_filter,
    WOLF_EVENT** events, int maxEvents, WOLF_EVENT_FLAG flags, int* eventCount)
{
    WOLF_EVENT* event;
    int ret = 0, count = 0;
    AsyncCryptDev* asyncDev = NULL;
#ifdef HAVE_CAVIUM
    CspMultiRequestStatusBuffer multi_req;
    XMEMSET(&multi_req, 0, sizeof(multi_req));
#endif

    /* possible un-used variable */
    (void)asyncDev;

    if (queue == NULL) {
        return BAD_FUNC_ARG;
    }

#ifndef SINGLE_THREADED
    /* In single threaded mode "event_queue.lock" doesn't exist */
    if ((ret = LockMutex(&queue->lock)) != 0) {
        return ret;
    }
#endif

    /* if check hardware flag is set */
    if (flags & WOLF_POLL_FLAG_CHECK_HW) {
        /* check event queue */
        count = 0;
        for (event = queue->head; event != NULL; event = event->next)
        {
            if (event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
                event->type <= WOLF_EVENT_TYPE_ASYNC_LAST)
            {
                /* optional filter based on context */
                if (context_filter == NULL || event->context == context_filter) {
                    asyncDev = (AsyncCryptDev*)event->context;
                    count++;
                
                #if defined(HAVE_CAVIUM)
                    /* Fill multi request status buffer */
                    if (event->reqId > 0) {
                        multi_req.req[multi_req.count].request_id = event->reqId;
                        multi_req.count++;
                    }

                    /* Note: event queue mutex is locked here, so make sure
                    hardware doesn't try and lock event_queue */
                    if (multi_req.count >= CAVIUM_MAX_POLL) {
                        ret = wolfAsync_CheckMultiReqBuf(asyncDev,
                                            queue, context_filter, &multi_req);
                        if (ret != 0) {
                            break;
                        }
                    }
                #elif defined(HAVE_INTEL_QA)
                    /* TODO: Add hardware polling for Intel QuickAssist */
                #else
                    #ifdef WOLF_ASYNC_TEST_SKIP_MOD
                        /* Simulate random hardware not done */
                        if (count % WOLF_ASYNC_TEST_SKIP_MOD)
                    #endif
                        {
                            event->ret = wolfAsync_crypt_test(event);
                        }
                #endif
                    (void)asyncDev; /* Ignore un-used warning */
                }
            }
        } /* for */

        /* check remainder */
    #if defined(HAVE_CAVIUM)
        if (ret == 0 && multi_req.count > 0) {
            ret = wolfAsync_CheckMultiReqBuf(asyncDev,
                                queue, context_filter, &multi_req);
        }
    #endif
    } /* flag WOLF_POLL_FLAG_CHECK_HW */

    /* process event queue */
    count = 0;
    for (event = queue->head; event != NULL; event = event->next)
    {
        if (event->type >= WOLF_EVENT_TYPE_ASYNC_FIRST &&
            event->type <= WOLF_EVENT_TYPE_ASYNC_LAST)
        {
            /* optional filter based on context */
            if (context_filter == NULL || event->context == context_filter) {
                /* If event is done then process */
                if (event->done) {
                    /* remove from queue */
                    ret = wolfEventQueue_Remove(queue, event);
                    if (ret < 0) break; /* exit for */

                    /* return pointer in 'events' arg */
                    if (events) {
                        events[count] = event; /* return pointer */
                    }
                    count++;

                    /* check to make sure our event list isn't full */
                    if (events && count >= maxEvents) {
                        break; /* exit for */
                    }
                }
            }
        }
    }

#ifndef SINGLE_THREADED
    UnLockMutex(&queue->lock);
#endif

    /* Return number of properly populated events */
    if (eventCount) {
        *eventCount = count;
    }

    return ret;
}

int wolfAsync_EventInit(WOLF_EVENT* event, WOLF_EVENT_TYPE type, void* context)
{
    int ret;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfEvent_Init(event, type, context);
    if (ret == 0) {
    #ifdef HAVE_CAVIUM
        AsyncCryptDev* asyncDev = (AsyncCryptDev*)event->context;
        event->reqId = asyncDev->dev.reqId;
    #elif defined(HAVE_INTEL_QA)
        /* TODO: Add any event init for Intel QuickAssist */
    #endif
        event->pending = 1;
        event->done = 0;
        event->ret = WC_PENDING_E;
        ret = 0;
    }

    return ret;
}

int wolfAsync_EventWait(WOLF_EVENT* event)
{
    int ret = 0;

    if (event == NULL) {
        return BAD_FUNC_ARG;
    }

    /* wait for completion */
    while (ret == 0 && event->ret == WC_PENDING_E) {
        ret = wolfAsync_EventPoll(event, WOLF_POLL_FLAG_CHECK_HW);
    }

    return ret;
}

#endif /* WOLFSSL_ASYNC_CRYPT */
