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
#include "external_interface.h"

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

int32_t RequestOhosDslmCred(const DeviceIdentify *device, const RequestObject *obj, DslmCredBuff **credBuff)
{
    SECURITY_LOG_INFO("Invoke RequestOhosDslmCred");

    char *pkInfoListStr = NULL;
    char *nounceStr = NULL;
    uint8_t *certChain = NULL;
    uint32_t certChainLen = 0;

    char credStr[CRED_STR_LEN_MAX] = {0};
    int32_t ret = GetCredFromCurrentDevice(credStr, CRED_STR_LEN_MAX);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("read data frome CFG failed!");
        return ret;
    }

    do {
        ret = GetPkInfoListStr(true, device->identity, device->length, &pkInfoListStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("GetPkInfoListStr failed");
            break;
        }

        ret = TransToJsonStr(obj->challenge, pkInfoListStr, &nounceStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("TransToJsonStr failed");
            break;
        }

        ret = DslmCredAttestAdapter(nounceStr, credStr, &certChain, &certChainLen);
        if (ret != SUCCESS) {
            SECURITY_LOG_INFO("DslmCredAttestAdapter failed");
            break;
        }

        DslmCredBuff *out = CreateDslmCred(CRED_TYPE_STANDARD, certChainLen, certChain);
        if (out == NULL) {
            ret = ERR_MEMORY_ERR;
            SECURITY_LOG_INFO("CreateDslmCred failed");
            break;
        }
        *credBuff = out;
        ret = SUCCESS;
    } while (0);

    

    if (pkInfoListStr != NULL) {
        FREE(pkInfoListStr);
    }
    if (nounceStr != NULL) {
        FREE(nounceStr);
    }
    if (certChain != NULL) {
        FREE(certChain);
    }
    return ret;
}
