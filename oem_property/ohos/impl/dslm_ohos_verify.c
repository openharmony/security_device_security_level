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

#include "dslm_ohos_verify.h"

#include <securec.h>
#include <string.h>

#include "utils_hexstring.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"

#include "dslm_credential_utils.h"
#include "dslm_crypto.h"
#include "external_interface_adapter.h"

#define UDID_STRING_LENGTH 65

#define CRED_MAX_LEVEL_TYPE_SMALL 2
#define CRED_MAX_LEVEL_TYPE_STANDARD 5

#define CRED_VALUE_TYPE_DEBUG "debug"
#define CRED_VALUE_TYPE_RELEASE "release"

#define DSLM_CRED_STR_LEN_MAX 4096

struct NounceOfCertChain {
    uint64_t challenge;
    uint8_t *pbkInfoList;
    uint32_t pbkInfoListLen;
};

static int32_t CheckCredInfo(const struct DeviceIdentify *device, DslmCredInfo *info, uint32_t maxLevel)
{
    SECURITY_LOG_DEBUG("CheckCredInfo start!");
    if (info->credLevel > maxLevel) {
        SECURITY_LOG_ERROR("Cred level = %{public}d check error.", info->credLevel);
        info->credLevel = 0;
        return ERR_CHECK_CRED_INFO;
    }
    if (strlen(info->udid) == 0) {
        SECURITY_LOG_DEBUG("Current cred has no udid, skip CheckCredInfo.");
        return SUCCESS;
    }
    if (strncmp(info->type, CRED_VALUE_TYPE_DEBUG, strlen(CRED_VALUE_TYPE_DEBUG)) == 0) {
        if (memcmp((char *)device->identity, info->udid, strlen(info->udid)) == 0) {
            return SUCCESS;
        }
        return ERR_CHECK_CRED_INFO;
    }
    SECURITY_LOG_DEBUG("CheckCredInfo SUCCESS!");
    return SUCCESS;
}

static int32_t ParseNounceOfCertChain(const char *jsonBuffer, struct NounceOfCertChain *nounce)
{
    JsonHandle json = CreateJson(jsonBuffer);
    if (json == NULL) {
        return ERR_INVALID_PARA;
    }

    // 1. Get challenge.
    const char *challengeStr = GetJsonFieldString(json, "challenge");
    if (challengeStr == NULL) {
        DestroyJson(json);
        return ERR_PARSE_NOUNCE;
    }
    int32_t ret =
        HexStringToByte(challengeStr, strlen(challengeStr), (uint8_t *)&nounce->challenge, sizeof(nounce->challenge));
    if (ret != SUCCESS) {
        DestroyJson(json);
        return ERR_PARSE_NOUNCE;
    }

    // 2. Get PublicKey Info.
    const char *pkInfoListStr = GetJsonFieldString(json, "pkInfoList");
    if (pkInfoListStr == NULL) {
        DestroyJson(json);
        return ERR_PARSE_NOUNCE;
    }
    nounce->pbkInfoList = (uint8_t *)MALLOC(strlen(pkInfoListStr) + 1);
    if (nounce->pbkInfoList == NULL) {
        DestroyJson(json);
        return ERR_NO_MEMORY;
    }

    ret = strcpy_s((char *)nounce->pbkInfoList, strlen(pkInfoListStr) + 1, pkInfoListStr);
    if (ret != EOK) {
        FREE(nounce->pbkInfoList);
        nounce->pbkInfoList = NULL;
        DestroyJson(json);
        return ERR_MEMORY_ERR;
    }
    DestroyJson(json);
    return SUCCESS;
}

static void FreeNounceOfCertChain(struct NounceOfCertChain *nounce)
{
    if (nounce == NULL) {
        return;
    }
    if (nounce->pbkInfoList != NULL) {
        FREE(nounce->pbkInfoList);
        nounce->pbkInfoList = NULL;
    }
    (void)memset_s(nounce, sizeof(struct NounceOfCertChain), 0, sizeof(struct NounceOfCertChain));
}

static int32_t FindCommonPkInfo(const char *bufferA, const char *bufferB)
{
    if (bufferA == NULL || bufferB == NULL) {
        return ERR_INVALID_PARA;
    }
    JsonHandle jsonA = CreateJson(bufferA);
    if (jsonA == NULL) {
        return ERR_INVALID_PARA;
    }
    JsonHandle jsonB = CreateJson(bufferB);
    if (jsonB == NULL) {
        DestroyJson(jsonA);
        return ERR_INVALID_PARA;
    }
    uint32_t sizeA = (uint32_t)GetJsonFieldJsonArraySize(jsonA);
    uint32_t sizeB = (uint32_t)GetJsonFieldJsonArraySize(jsonB);

    for (uint32_t i = 0; i < sizeA; i++) {
        for (uint32_t j = 0; j < sizeB; j++) {
            if (CompareJsonData(GetJsonFieldJsonArray(jsonA, i), GetJsonFieldJsonArray(jsonB, j), true)) {
                DestroyJson(jsonA);
                DestroyJson(jsonB);
                return SUCCESS;
            }
        }
    }
    DestroyJson(jsonA);
    DestroyJson(jsonB);
    return ERR_NOEXIST_COMMON_PK_INFO;
}

static int32_t CheckNounceOfCertChain(const struct NounceOfCertChain *nounce, uint64_t challenge,
    const char *pbkInfoList)
{
    if (challenge != nounce->challenge) {
        SECURITY_LOG_ERROR("compare nounce challenge failed!");
        return ERR_CHALLENGE_ERR;
    }

    int32_t ret = FindCommonPkInfo((char *)pbkInfoList, (char *)nounce->pbkInfoList);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("compare nounce public key info failed!");
        return ret;
    }
    return SUCCESS;
}

static int32_t VerifyNounceOfCertChain(const char *jsonStr, const struct DeviceIdentify *device, uint64_t challenge)
{
    char *pkInfoListStr = NULL;
    struct NounceOfCertChain nounce;
    (void)memset_s(&nounce, sizeof(struct NounceOfCertChain), 0, sizeof(struct NounceOfCertChain));

    char udidStr[UDID_STRING_LENGTH] = {0};
    if (memcpy_s(udidStr, UDID_STRING_LENGTH, device->identity, device->length) != EOK) {
        return ERR_MEMORY_ERR;
    }

    int32_t ret = ERR_DEFAULT;
    do {
        ret = ParseNounceOfCertChain(jsonStr, &nounce);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("ParseNounceOfCertChain failed!");
            break;
        }

        ret = GetPkInfoListStr(false, udidStr, &pkInfoListStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("GetPkInfoListStr failed!");
            break;
        }

        ret = CheckNounceOfCertChain(&nounce, challenge, pkInfoListStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("CheckNounceOfCertChain failed!");
            break;
        }
        SECURITY_LOG_DEBUG("VerifyNounceOfCertChain success!");
    } while (0);

    FreeNounceOfCertChain(&nounce);
    FREE(pkInfoListStr);
    return ret;
}

static int32_t verifySmallDslmCred(const DeviceIdentify *device, const DslmCredBuff *credBuff, DslmCredInfo *credInfo)
{
    char credStr[DSLM_CRED_STR_LEN_MAX] = {0};
    if (memcpy_s(credStr, DSLM_CRED_STR_LEN_MAX, credBuff->credVal, credBuff->credLen + 1) != EOK) {
        return ERR_MEMORY_ERR;
    }

    int32_t ret = VerifyDslmCredential(credStr, credInfo, NULL);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("VerifyCredData failed!");
        return ret;
    }

    ret = CheckCredInfo(device, credInfo, CRED_MAX_LEVEL_TYPE_SMALL);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("CheckCredInfo failed!");
        return ret;
    }

    return SUCCESS;
}

static int32_t verifyStandardDslmCred(const DeviceIdentify *device, uint64_t challenge, const DslmCredBuff *credBuff,
    DslmCredInfo *credInfo)
{
    struct DslmInfoInCertChain resultInfo;
    int32_t ret = InitDslmInfoInCertChain(&resultInfo);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("InitDslmInfoInCertChain failed!");
        return ret;
    }

    do {
        // 1. Verify the certificate chain, get data in the certificate chain(nounce + UDID + cred).
        ret = ValidateCertChainAdapter(credBuff->credVal, credBuff->credLen, &resultInfo);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("ValidateCertChainAdapter failed!");
            break;
        }

        // 2. Parses the NOUNCE into CHALLENGE and PK_INFO_LIST, verifies them separtely.
        ret = VerifyNounceOfCertChain(resultInfo.nounceStr, device, challenge);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("verifyNounceOfCertChain failed!");
            break;
        }

        // 3. The cred content is "<header>.<payload>.<signature>.<attestion>", parse and verify it.
        ret = VerifyDslmCredential(resultInfo.credStr, credInfo, NULL);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("VerifyCredData failed!");
            break;
        }
        ret = CheckCredInfo(device, credInfo, CRED_MAX_LEVEL_TYPE_STANDARD);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("CheckCredInfo failed!");
            break;
        }
    } while (0);

    DestroyDslmInfoInCertChain(&resultInfo);
    if (ret == SUCCESS) {
        SECURITY_LOG_INFO("cred level = %{public}d", credInfo->credLevel);
        SECURITY_LOG_INFO("VerifyOhosDslmCred SUCCESS!");
    }
    return ret;
}

int32_t VerifyOhosDslmCred(const DeviceIdentify *device, uint64_t challenge, const DslmCredBuff *credBuff,
    DslmCredInfo *credInfo)
{
    SECURITY_LOG_INFO("Invoke VerifyOhosDslmCred");

    switch (credBuff->type) {
        case CRED_TYPE_SMALL:
            return verifySmallDslmCred(device, credBuff, credInfo);
        case CRED_TYPE_STANDARD:
            return verifyStandardDslmCred(device, challenge, credBuff, credInfo);
        default:
            SECURITY_LOG_ERROR("Invalid cred type!");
            break;
    }
    return ERR_INVALID_PARA;
}