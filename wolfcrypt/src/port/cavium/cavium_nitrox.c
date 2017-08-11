/* cavium-nitrox.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_CAVIUM

#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif

#include <wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h>
#include <netinet/in.h> /* For ntohs */

static CspHandle mLastDevHandle = INVALID_DEVID;

#ifndef NITROX_MAX_BUF_LEN
    /* max buffer pool size is 32768, but need to leave room for request */
    #define NITROX_MAX_BUF_LEN (32768U / 2)
#endif

int NitroxTranslateResponseCode(int ret)
{
    switch (ret) {
        case EAGAIN:
        case ERR_REQ_PENDING:
        case REQUEST_PENDING:
            ret = WC_PENDING_E;
            break;
        case ERR_REQ_TIMEOUT:
            ret = WC_TIMEOUT_E;
            break;
        case ERR_DATA_LEN_INVALID:
            ret = BAD_FUNC_ARG;
            break;
        case 0:
        case 1:
            ret = 0; /* treat as success */
            break;
        default:
            printf("NitroxTranslateResponseCode Unknown ret=0x%x\n", ret);
            ret = ASYNC_INIT_E;
    }
    return ret;
}

static INLINE void NitroxDevClear(WC_ASYNC_DEV* dev)
{
    /* values that must be reset prior to calling algo */
    /* this is because operation may complete before added to event list */
    dev->event.ret = WC_PENDING_E;
    dev->event.state = WOLF_EVENT_STATE_PENDING;
}

CspHandle NitroxGetDeviceHandle(void)
{
    return mLastDevHandle;
}

CspHandle NitroxOpenDevice(int dma_mode, int dev_id)
{
    mLastDevHandle = INVALID_DEVID;

#ifdef HAVE_CAVIUM_V
    (void)dma_mode;

    if (CspInitialize(dev_id, &mLastDevHandle)) {
        return -1;
    }

#else
    Csp1CoreAssignment core_assign;
    Uint32             device;

    if (CspInitialize(CAVIUM_DIRECT, CAVIUM_DEV_ID)) {
        return -1;
    }
    if (Csp1GetDevType(&device)) {
        return -1;
    }
    if (device != NPX_DEVICE) {
        if (ioctl(gpkpdev_hdlr[CAVIUM_DEV_ID], IOCTL_CSP1_GET_CORE_ASSIGNMENT,
        (Uint32 *)&core_assign)!= 0) {
            return -1;
        }
    }
    CspShutdown(CAVIUM_DEV_ID);

    mLastDevHandle = CspInitialize(dma_mode, dev_id);
    if (mLastDevHandle == 0) {
        mLastDevHandle = dev_id;
    }

#endif /* HAVE_CAVIUM_V */

    return mLastDevHandle;
}


int NitroxAllocContext(WC_ASYNC_DEV* dev, CspHandle devId,
    ContextType type)
{
    int ret;

    if (dev == NULL) {
        return -1;
    }

    /* If invalid handle provided, use last open one */
    if (devId == INVALID_DEVID) {
        devId = NitroxGetDeviceHandle();
    }

#ifdef HAVE_CAVIUM_V
    ret = CspAllocContext(devId, type, &dev->nitrox.contextHandle);
#else
    ret = CspAllocContext(type, &dev->nitrox.contextHandle, devId);
#endif
    if (ret != 0) {
        return -1;
    }

    dev->nitrox.type = type;
    dev->nitrox.devId = devId;

    return 0;
}

void NitroxFreeContext(WC_ASYNC_DEV* dev)
{
    if (dev == NULL) {
        return;
    }

#ifdef HAVE_CAVIUM_V
    CspFreeContext(dev->nitrox.devId, dev->nitrox.type,
        dev->nitrox.contextHandle);
#else
    CspFreeContext(dev->nitrox.type, dev->nitrox.contextHandle,
        dev->nitrox.devId);
#endif
}

void NitroxCloseDevice(CspHandle devId)
{
    if (devId >= 0) {
        CspShutdown(devId);
    }
}

#if defined(WOLFSSL_ASYNC_CRYPT)

int NitroxCheckRequest(WC_ASYNC_DEV* dev, WOLF_EVENT* event)
{
    int ret = CspCheckForCompletion(dev->nitrox.devId, event->reqId);
    return NitroxTranslateResponseCode(ret);
}

int NitroxCheckRequests(WC_ASYNC_DEV* dev,
    struct CspMultiRequestStatusBuffer* req_stat_buf)
{
    int ret = CspGetAllResults(req_stat_buf, dev->nitrox.devId);
    return NitroxTranslateResponseCode(ret);
}


#ifndef NO_RSA

int NitroxRsaExptMod(const byte* in, word32 inLen,
                     byte* exponent, word32 expLen,
                     byte* modulus, word32 modLen,
                     byte* out, word32* outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || inLen == 0 || exponent == NULL ||
                                            modulus == NULL || out == NULL) {
        return BAD_FUNC_ARG;
    }

    (void)outLen;

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspMe(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE, CAVIUM_SSL_GRP,
            CAVIUM_DPORT, modLen, expLen, inLen, modulus, exponent, (Uint8*)in,
            out, &key->asyncDev.nitrox.reqId);
    #if 0
    /* TODO: Try MeCRT */
    ret = CspMeCRT();
    #endif
#else
    /* Not implemented/supported */
    ret = NOT_COMPILED_IN;
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return ret;
}

int NitroxRsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                           word32 outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL ||
                                            outLen < (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15Enc(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT2, key->n.raw.len, key->e.raw.len,
        (word16)inLen, key->n.raw.buf, key->e.raw.buf, (byte*)in, out,
        &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15Enc(CAVIUM_REQ_MODE, BT2, key->n.raw.len, key->e.raw.len,
        (word16)inLen, key->n.raw.buf, key->e.raw.buf, (byte*)in, out,
        &key->asyncDev.nitrox.reqId, key->asyncDev.nitrox.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return key->n.raw.len;
}


static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}

int NitroxRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                            word32* outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL ||
                                            inLen != (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15CrtDec(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT2, key->n.raw.len, key->q.raw.buf,
        key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf, key->u.raw.buf,
        (byte*)in, (Uint16*)outLen, out, &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15CrtDec(CAVIUM_REQ_MODE, BT2, key->n.raw.len,
        key->q.raw.buf, key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf,
        key->u.raw.buf, (byte*)in, &outLen, out, &key->asyncDev.nitrox.reqId,
        key->asyncDev.nitrox.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    ato16((const byte*)outLen, (word16*)outLen);

    return *outLen;
}


int NitroxRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                      word32 outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL || inLen == 0 || outLen <
                                                     (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15CrtEnc(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT1, key->n.raw.len, (word16)inLen,
        key->q.raw.buf, key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf,
        key->u.raw.buf, (byte*)in, out, &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15CrtEnc(CAVIUM_REQ_MODE, BT1, key->n.raw.len,(word16)inLen,
        key->q.raw.buf, key->dQ.raw.buf, key->p.raw.buf, key->dP.raw.buf,
        key->u.raw.buf, (byte*)in, out, &key->asyncDev.nitrox.reqId,
        key->asyncDev.nitrox.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    return key->n.raw.len;
}


int NitroxRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                        word32* outLen, RsaKey* key)
{
    int ret;

    if (key == NULL || in == NULL || out == NULL || inLen != (word32)key->n.raw.len) {
        return BAD_FUNC_ARG;
    }

    /* init return codes */
    NitroxDevClear(&key->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspPkcs1v15Dec(key->asyncDev.nitrox.devId, CAVIUM_REQ_MODE,
        CAVIUM_SSL_GRP, CAVIUM_DPORT, BT1, key->n.raw.len, key->e.raw.len,
        key->n.raw.buf, key->e.raw.buf, (byte*)in, (Uint16*)outLen, out,
        &key->asyncDev.nitrox.reqId);
#else
    ret = CspPkcs1v15Dec(CAVIUM_REQ_MODE, BT1, key->n.raw.len, key->e.raw.len,
        key->n.raw.buf, key->e.raw.buf, (byte*)in, &outLen, out,
        &key->asyncDev.nitrox.reqId, key->asyncDev.nitrox.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    *outLen = ntohs(*outLen);

    return *outLen;
}
#endif /* !NO_RSA */


#ifndef NO_AES

#ifdef HAVE_AES_CBC
static int NitroxAesGetType(Aes* aes, AesType* type)
{
    int ret = 0;
    if (aes->keylen == 16)
        *type = AES_128_BIT;
    else if (aes->keylen == 24)
        *type = AES_192_BIT;
    else if (aes->keylen == 32)
        *type = AES_256_BIT;
    else
        ret = BAD_FUNC_ARG;
    return ret;
}

int NitroxAesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 length)
{
    int ret;
    wolfssl_word offset = 0;
    AesType type;

    ret = NitroxAesGetType(aes, &type);
    if (ret != 0) {
        return ret;
    }

    /* init return codes */
    NitroxDevClear(&aes->asyncDev);

    while (length > NITROX_MAX_BUF_LEN) {
        word16 slen = (word16)NITROX_MAX_BUF_LEN;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncryptAes(aes->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            aes->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, AES_CBC,
            type, (byte*)aes->asyncKey, (byte*)aes->asyncIv, 0, NULL, NULL,
            slen, (byte*)in + offset, out + offset,
            &aes->asyncDev.nitrox.reqId);
    #else
        ret = CspEncryptAes(CAVIUM_BLOCKING, aes->asyncDev.nitrox.contextHandle,
            CAVIUM_NO_UPDATE, type, slen, (byte*)in + offset, out + offset,
            (byte*)aes->asyncIv, (byte*)aes->asyncKey,
            &aes->asyncDev.nitrox.reqId, aes->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= NITROX_MAX_BUF_LEN;
        offset += NITROX_MAX_BUF_LEN;
        XMEMCPY(aes->reg, out + offset - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncryptAes(aes->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            aes->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, AES_CBC,
            type, (byte*)aes->asyncKey, (byte*)aes->asyncIv,  0, NULL, NULL,
            slen, (byte*)in + offset, out + offset,
            &aes->asyncDev.nitrox.reqId);
    #else
        ret = CspEncryptAes(CAVIUM_BLOCKING, aes->asyncDev.nitrox.contextHandle,
            CAVIUM_NO_UPDATE, type, slen, (byte*)in + offset, out + offset,
            (byte*)aes->asyncIv, (byte*)aes->asyncKey,
            &aes->asyncDev.nitrox.reqId, aes->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(aes->reg, out + offset+length - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
    return 0;
}

#ifdef HAVE_AES_DECRYPT
int NitroxAesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 length)
{
    int ret;
    wolfssl_word offset = 0;
    AesType type;

    ret = NitroxAesGetType(aes, &type);
    if (ret != 0) {
        return ret;
    }

    /* init return codes */
    NitroxDevClear(&aes->asyncDev);

    while (length > NITROX_MAX_BUF_LEN) {
        word16 slen = (word16)NITROX_MAX_BUF_LEN;
        XMEMCPY(aes->tmp, in + offset + slen - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecryptAes(aes->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            aes->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, AES_CBC,
            type, (byte*)aes->asyncKey, (byte*)aes->asyncIv, 0, NULL, NULL,
            slen, (byte*)in + offset, out + offset,
            &aes->asyncDev.nitrox.reqId);
    #else
        ret = CspDecryptAes(CAVIUM_BLOCKING, aes->asyncDev.nitrox.contextHandle,
            CAVIUM_NO_UPDATE, type, slen, (byte*)in + offset, out + offset,
            (byte*)aes->asyncIv, (byte*)aes->asyncKey,
            &aes->asyncDev.nitrox.reqId, aes->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= NITROX_MAX_BUF_LEN;
        offset += NITROX_MAX_BUF_LEN;
        XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
        XMEMCPY(aes->tmp, in + offset + slen - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecryptAes(aes->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            aes->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, AES_CBC,
            type, (byte*)aes->asyncKey, (byte*)aes->asyncIv, 0, NULL, NULL,
            slen, (byte*)in + offset, out + offset,
            &aes->asyncDev.nitrox.reqId);
    #else
        ret = CspDecryptAes(CAVIUM_BLOCKING, aes->asyncDev.nitrox.contextHandle,
            CAVIUM_NO_UPDATE, type, slen, (byte*)in + offset, out + offset,
            (byte*)aes->asyncIv, (byte*)aes->asyncKey,
            &aes->asyncDev.nitrox.reqId, aes->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(aes->reg, aes->tmp, AES_BLOCK_SIZE);
    }
    return 0;
}
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */
#endif /* !NO_AES */


#if !defined(NO_ARC4) && !defined(HAVE_CAVIUM_V)
void NitroxArc4SetKey(Arc4* arc4, const byte* key, word32 length)
{
    if (CspInitializeRc4(CAVIUM_BLOCKING, arc4->asyncDev.nitrox.contextHandle,
          length, (byte*)key, &arc4->asyncDev.nitrox.reqId, arc4->devId) != 0) {
        WOLFSSL_MSG("Bad Cavium Arc4 Init");
    }
}

void NitroxArc4Process(Arc4* arc4, byte* out, const byte* in, word32 length)
{
    int ret;
    wolfssl_word offset = 0;

    /* init return codes */
    NitroxDevClear(&arc4->asyncDev);

    while (length > NITROX_MAX_BUF_LEN) {
        word16 slen = (word16)NITROX_MAX_BUF_LEN;
        ret = CspEncryptRc4(CAVIUM_BLOCKING,
            arc4->asyncDev.nitrox.contextHandle, CAVIUM_UPDATE, slen,
            (byte*)in + offset, out + offset,
            &arc4->asyncDev.nitrox.reqId, arc4->devId);
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= NITROX_MAX_BUF_LEN;
        offset += NITROX_MAX_BUF_LEN;
    }
    if (length) {
        word16 slen = (word16)length;
        ret = CspEncryptRc4(CAVIUM_BLOCKING,
            arc4->asyncDev.nitrox.contextHandle, CAVIUM_UPDATE, slen,
            (byte*)in + offset, out + offset,
            &arc4->asyncDev.nitrox.reqId, arc4->devId);
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
    }
}
#endif /* !NO_ARC4 && !HAVE_CAVIUM_V */


#ifndef NO_DES3
int NitroxDes3CbcEncrypt(Des3* des3, byte* out, const byte* in, word32 length)
{
    wolfssl_word offset = 0;
    int ret;

    /* init return codes */
    NitroxDevClear(&des3->asyncDev);

    while (length > NITROX_MAX_BUF_LEN) {
        word16 slen = (word16)NITROX_MAX_BUF_LEN;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncrypt3Des(des3->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            des3->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, DES3_CBC,
            (byte*)des3->key_raw, (byte*)des3->iv_raw, slen, (byte*)in + offset,
            out + offset, &des3->asyncDev.nitrox.reqId);
    #else
        ret = CspEncrypt3Des(CAVIUM_BLOCKING,
            des3->asyncDev.nitrox.contextHandle, CAVIUM_NO_UPDATE, slen,
            (byte*)in + offset, out + offset, (byte*)des3->iv_raw,
            (byte*)des3->key_raw, &des3->asyncDev.nitrox.reqId,
            des3->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= NITROX_MAX_BUF_LEN;
        offset += NITROX_MAX_BUF_LEN;
        XMEMCPY(des3->reg, out + offset - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
    #ifdef HAVE_CAVIUM_V
        ret = CspEncrypt3Des(des3->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            des3->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, DES3_CBC,
            (byte*)des3->key_raw, (byte*)des3->iv_raw, slen, (byte*)in + offset,
            out + offset, &des3->asyncDev.nitrox.reqId);
    #else
        ret = CspEncrypt3Des(CAVIUM_BLOCKING,
            des3->asyncDev.nitrox.contextHandle, CAVIUM_NO_UPDATE, slen,
            (byte*)in + offset, out + offset, (byte*)des3->iv_raw,
            (byte*)des3->key_raw, &des3->asyncDev.nitrox.reqId,
            des3->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(des3->reg, out+offset+length - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    }
    return 0;
}

int NitroxDes3CbcDecrypt(Des3* des3, byte* out, const byte* in, word32 length)
{
    wolfssl_word offset = 0;
    int ret;

    /* init return codes */
    NitroxDevClear(&des3->asyncDev);

    while (length > NITROX_MAX_BUF_LEN) {
        word16 slen = (word16)NITROX_MAX_BUF_LEN;
        XMEMCPY(des3->tmp, in + offset + slen - DES_BLOCK_SIZE, DES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecrypt3Des(des3->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            des3->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, DES3_CBC,
            (byte*)des3->key_raw, (byte*)des3->iv_raw, slen, (byte*)in + offset,
            out + offset, &des3->asyncDev.nitrox.reqId);
    #else
        ret = CspDecrypt3Des(CAVIUM_BLOCKING,
            des3->asyncDev.nitrox.contextHandle, CAVIUM_NO_UPDATE, slen,
            (byte*)in + offset, out + offset, (byte*)des3->iv_raw,
            (byte*)des3->key_raw, &des3->asyncDev.nitrox.reqId,
            des3->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        length -= NITROX_MAX_BUF_LEN;
        offset += NITROX_MAX_BUF_LEN;
        XMEMCPY(des3->reg, des3->tmp, DES_BLOCK_SIZE);
    }
    if (length) {
        word16 slen = (word16)length;
        XMEMCPY(des3->tmp, in + offset + slen - DES_BLOCK_SIZE,DES_BLOCK_SIZE);
    #ifdef HAVE_CAVIUM_V
        ret = CspDecrypt3Des(des3->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT,
            des3->asyncDev.nitrox.contextHandle, FROM_DPTR, FROM_CTX, DES3_CBC,
            (byte*)des3->key_raw, (byte*)des3->iv_raw, slen, (byte*)in + offset,
            out + offset, &des3->asyncDev.nitrox.reqId);
    #else
        ret = CspDecrypt3Des(CAVIUM_BLOCKING,
            des3->asyncDev.nitrox.contextHandle, CAVIUM_NO_UPDATE, slen,
            (byte*)in + offset, out + offset, (byte*)des3->iv_raw,
            (byte*)des3->key_raw, &des3->asyncDev.nitrox.reqId,
            des3->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        XMEMCPY(des3->reg, des3->tmp, DES_BLOCK_SIZE);
    }
    return 0;
}
#endif /* !NO_DES3 */


#ifndef NO_HMAC
static int NitroxHmacGetType(int type)
{
    int cav_type = -1;

    /* Determine Cavium HashType */
    switch(type) {
    #ifndef NO_MD5
        case MD5:
            cav_type = MD5_TYPE;
            break;
    #endif
    #ifndef NO_SHA
        case SHA:
            cav_type = SHA1_TYPE;
            break;
    #endif
    #ifndef NO_SHA256
    #ifdef WOLFSSL_SHA224
        case SHA224:
        #ifdef HAVE_CAVIUM_V
            cav_type = SHA2_SHA224;
        #else
            cav_type = SHA224_TYPE;
        #endif
            break;
    #endif /* WOLFSSL_SHA224 */
        case SHA256:
        #ifdef HAVE_CAVIUM_V
            cav_type = SHA2_SHA256;
        #else
            cav_type = SHA256_TYPE;
        #endif
            break;
    #endif
    #ifdef HAVE_CAVIUM_V
        #ifdef WOLFSSL_SHA512
            case SHA512:
                cav_type = SHA2_SHA512;
                break;
        #endif
        #ifdef WOLFSSL_SHA384
            case SHA384:
                cav_type = SHA2_SHA384;
                break;
        #endif
    #endif /* HAVE_CAVIUM_V */
        default:
            WOLFSSL_MSG("unsupported cavium hmac type");
            cav_type = -1;
            break;
    }

    return cav_type;
}

int NitroxHmacUpdate(Hmac* hmac, const byte* msg, word32 length)
{
    word16 add = (word16)length;
    word32 total;
    byte*  tmp;

    if (length > NITROX_MAX_BUF_LEN) {
        WOLFSSL_MSG("Too big msg for cavium hmac");
        return BUFFER_E;
    }

    if (hmac->innerHashKeyed == 0) {  /* starting new */
        hmac->dataLen        = 0;
        hmac->innerHashKeyed = 1;
    }

    total = add + hmac->dataLen;
    if (total > NITROX_MAX_BUF_LEN) {
        WOLFSSL_MSG("Too big msg for cavium hmac");
        return BUFFER_E;
    }

    tmp = XMALLOC(hmac->dataLen + add, hmac->heap, DYNAMIC_TYPE_HMAC);
    if (tmp == NULL) {
        WOLFSSL_MSG("Out of memory for cavium update");
        return MEMORY_E;
    }
    if (hmac->dataLen)
        XMEMCPY(tmp, hmac->data,  hmac->dataLen);
    XMEMCPY(tmp + hmac->dataLen, msg, add);

    hmac->dataLen += add;
    XFREE(hmac->data, hmac->heap, DYNAMIC_TYPE_HMAC);
    hmac->data = tmp;

    return 0;
}

int NitroxHmacFinal(Hmac* hmac, int type, byte* hash, word16 hashLen)
{
    int ret;
    int cav_type = NitroxHmacGetType(type);

    if (cav_type == -1) {
        return NOT_COMPILED_IN;
    }

    /* init return codes */
    NitroxDevClear(&hmac->asyncDev);

#ifdef HAVE_CAVIUM_V
    ret = CspHmac(hmac->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
        DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT, cav_type,
        hmac->keyLen, (byte*)hmac->ipad, hmac->dataLen, hmac->data, hashLen,
        hash, &hmac->asyncDev.nitrox.reqId);
#else
    (void)hashLen;
    ret = CspHmac(CAVIUM_BLOCKING, cav_type, NULL, hmac->keyLen,
        (byte*)hmac->ipad, hmac->dataLen, hmac->data, hash,
        &hmac->asyncDev.nitrox.reqId, hmac->asyncDev.nitrox.devId);
#endif
    ret = NitroxTranslateResponseCode(ret);
    if (ret != 0) {
        return ret;
    }

    hmac->innerHashKeyed = 0;  /* tell update to start over if used again */

    return ret;
}
#endif /* !NO_HMAC */

int NitroxRngGenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    int ret;
    wolfssl_word offset = 0;
    CavReqId     requestId;

    /* init return codes */
    NitroxDevClear(&rng->asyncDev);

    while (sz > NITROX_MAX_BUF_LEN) {
        word16 slen = (word16)NITROX_MAX_BUF_LEN;
    #ifdef HAVE_CAVIUM_V
        ret = CspTrueRandom(rng->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT, slen,
            output + offset, &requestId);
    #else
        ret = CspRandom(CAVIUM_BLOCKING, slen, output + offset, &requestId,
            rng->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
        sz     -= NITROX_MAX_BUF_LEN;
        offset += NITROX_MAX_BUF_LEN;
    }
    if (sz) {
        word16 slen = (word16)sz;
    #ifdef HAVE_CAVIUM_V
        ret = CspTrueRandom(rng->asyncDev.nitrox.devId, CAVIUM_BLOCKING,
            DMA_DIRECT_DIRECT, CAVIUM_SSL_GRP, CAVIUM_DPORT, slen,
            output + offset, &requestId);
    #else
        ret = CspRandom(CAVIUM_BLOCKING, slen, output + offset, &requestId,
            rng->asyncDev.nitrox.devId);
    #endif
        ret = NitroxTranslateResponseCode(ret);
        if (ret != 0) {
            return ret;
        }
    }

    return ret;
}

#endif /* WOLFSSL_ASYNC_CRYPT */

#endif /* HAVE_CAVIUM */
