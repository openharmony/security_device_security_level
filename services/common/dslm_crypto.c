/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dslm_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "device_security_defines.h"
#include "utils_log.h"

void GenerateRandom(RandomValue *rand, uint32_t length)
{
    if (rand == NULL) {
        return;
    }
    rand->length = (length > RAMDOM_MAX_LEN) ? RAMDOM_MAX_LEN : length;

    RAND_bytes(&rand->value[0], rand->length);
}

int32_t EcdsaVerify(const struct DataBuffer *srcData, const struct DataBuffer *sigData,
    const struct DataBuffer *pbkData, uint32_t algorithm)
{
    if (srcData == NULL || sigData == NULL || pbkData == NULL) {
        return ERR_INVALID_PARA;
    }
    if (srcData->data == NULL || sigData->data == NULL || pbkData->data == NULL || srcData->length == 0 ||
        sigData->length == 0 || pbkData->length == 0) {
        return ERR_INVALID_PARA;
    }
    if ((algorithm != TYPE_ECDSA_SHA_256) && (algorithm != TYPE_ECDSA_SHA_384)) {
        return ERR_INVALID_PARA;
    }

    int32_t ret = ERR_ECC_VERIFY_ERR;
    uint8_t *publicKey = pbkData->data;
    const EVP_MD *type = (algorithm == TYPE_ECDSA_SHA_256) ? EVP_sha256() : EVP_sha384();
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&(publicKey), pbkData->length);
    if (pkey == NULL) {
        return ret;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return ret;
    }

    do {
        ret = EVP_DigestVerifyInit(ctx, NULL, type, NULL, pkey);
        if (ret != 1) {
            break;
        }
        if (srcData == NULL) {
            SECURITY_LOG_ERROR("srcData  NULL!");
        }
        ret = EVP_DigestUpdate(ctx, srcData->data, srcData->length);
        if (ret != 1) {
            break;
        }
        if (EVP_DigestVerifyFinal(ctx, sigData->data, sigData->length) <= 0) {
            break;
        }
        ret = SUCCESS;
    } while (0);

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}

void CallHashSha256(const uint8_t *data, uint32_t dataLen, uint8_t *out)
{
    SHA256_CTX sctx;
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, data, dataLen);
    SHA256_Final(out, &sctx);
}