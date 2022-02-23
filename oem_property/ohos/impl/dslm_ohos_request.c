/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dslm_ohos_request.h"
#include "external_interface_adapter.h"

#include <securec.h>
#include <string.h>

#include "utils_hexstring.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"

#define CRED_CFG_FILE_POSITION "/system/etc/dslm_finger.cfg"
#define CRED_STR_LEN_MAX 4096
#define CHALLENGE_STRING_LENGTH 32

static int32_t GetCredFromCurrentDevice(char *credStr, uint32_t maxLen)
{
    FILE *fp = NULL;
    fp = fopen(CRED_CFG_FILE_POSITION, "r");
    if (fp == NULL) {
        SECURITY_LOG_INFO("fopen cred file failed!");
        return ERR_INVALID_PARA;
    }
    int32_t ret = fscanf_s(fp, "%s", credStr, maxLen);
    if (ret == -1) {
        ret = ERR_INVALID_PARA;
    } else {
        ret = SUCCESS;
    }
    if (fclose(fp) != 0) {
        ret = ERR_INVALID_PARA;
    }
    return ret;
}

static int32_t TransToJsonStr(uint64_t challenge, const char *pkInfoListStr, char **nounceStr)
{
    JsonHandle json = CreateJson(NULL);
    if (json == NULL) {
        return ERR_INVALID_PARA;
    }

    // add challenge
    char challengeStr[CHALLENGE_STRING_LENGTH] = {0};
    char *saveData = &challengeStr[0];
    ByteToHexString((uint8_t *)&challenge, sizeof(challenge), (uint8_t *)saveData, CHALLENGE_STRING_LENGTH);
    AddFieldStringToJson(json, "challenge", saveData);

    // add pkInfoList
    AddFieldStringToJson(json, "pkInfoList", pkInfoListStr);

    // tran to json
    *nounceStr = (char *)ConvertJsonToString(json);
    if (*nounceStr == NULL) {
        DestroyJson(json);
        return ERR_JSON_ERR;
    }
    DestroyJson(json);
    return SUCCESS;
}

static int32_t GenerateDslmCertChain(const DeviceIdentify *device, const RequestObject *obj, char* credStr, 
    uint8_t **certChain, uint32_t *certChainLen)
{
    char *pkInfoListStr = NULL;
    char *nounceStr = NULL;
    struct DslmInfoInCertChain saveInfo; 

    char udidStr[65] = {0};
    if (memcpy_s(udidStr, 65, device->identity, device->length) != EOK) {
        return ERR_MEMORY_ERR;
    }
    int32_t ret = ERR_DEFAULT;
    do {
        ret = GetPkInfoListStr(true, udidStr, &pkInfoListStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("GetPkInfoListStr failed");
            break;
        }

        ret = TransToJsonStr(obj->challenge, pkInfoListStr, &nounceStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("TransToJsonStr failed");
            break;
        }
    

        ret = FillDslmInfoInCertChain(&saveInfo, credStr, nounceStr, udidStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("FillDslmInfoInCertChain failed");
            break;
        }

        ret = DslmCredAttestAdapter(&saveInfo, certChain, certChainLen);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("DslmCredAttestAdapter failed");
            break;
        }
    } while (0);

    if (pkInfoListStr != NULL) {
        FREE(pkInfoListStr);
    }
    if (pkInfoListStr != NULL) {
        FREE(nounceStr);
    }
    return ret;
}


int32_t RequestOhosDslmCred(const DeviceIdentify *device, const RequestObject *obj, DslmCredBuff **credBuff)
{
    SECURITY_LOG_INFO("Invoke RequestOhosDslmCred");

    char credStr[CRED_STR_LEN_MAX] = {0};
    DslmCredBuff *out = NULL;
    int32_t ret = GetCredFromCurrentDevice(credStr, CRED_STR_LEN_MAX);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("Read cred data from file failed!");
        return ret;
    }
    if (HksAttestIsReadyAdapter() != SUCCESS) {
        // small type
        out = CreateDslmCred(CRED_TYPE_SMALL, strlen(credStr), (uint8_t*)credStr);
    } else {
        // standard type
   
        uint8_t *certChain = NULL;      // malloc, need free
        uint32_t certChainLen = 0;
        ret = GenerateDslmCertChain(device, obj, credStr, &certChain, &certChainLen);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("GenerateCertChain failed!");
            if (certChain != NULL) {
                FREE(certChain);
            }
            return ret;
        }
        out = CreateDslmCred(CRED_TYPE_STANDARD, certChainLen, certChain);
        if (certChain != NULL) {
            FREE(certChain);
        }

    }
    if (out == NULL) {
        SECURITY_LOG_INFO("CreateDslmCred failed");
        return ERR_MEMORY_ERR;
    }
    *credBuff = out;
    SECURITY_LOG_INFO("RequestOhosDslmCred success!");
    return SUCCESS;
}
   
