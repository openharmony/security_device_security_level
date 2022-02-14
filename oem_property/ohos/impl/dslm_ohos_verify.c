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

#include "dslm_crypto.h"
#include "external_interface.h"
#include "utils_base64.h"
#include "utils_hexstring.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"

#define OHOS_DEFAULT_LEVEL 1

#define DEVICE_LEVEL_CRED_TYPE_CRED_CLOUD_WITH_HUKS 100

#define UDID_STRING_LENGTH 65

#define SHA_256_HASH_RESULT_LEN 32

#define PBK_CHAIN_LEVEL 3
#define PBK_CHAIN_THIRD_KEY_INDEX 2

#define JSON_KEY_USER_PUBLIC_KEY    "userPublicKey"
#define JSON_KEY_SIGNATURE          "signature"
#define JSON_KEY_ALGORITHM          "algorithm"

#define SEC_LEVEL_STR_LEN           3   // "SL0"
#define CLOUD_CRED_SEC_LEVEL_0      0
#define CLOUD_CRED_SEC_LEVEL_MAX    5

#define CRED_KEY_CRED_VERSION       "version"
#define CRED_KEY_MANUFACTURE        "manufacture"
#define CRED_KEY_MODEL_NAME         "model"
#define CRED_KEY_BRAND              "brand"
#define CRED_KEY_OS_VERSION         "softwareVersion"
#define CRED_KEY_UDID               "udid"
#define CRED_KEY_TYPE               "type"
#define CRED_KEY_SIGN_TIME          "signTime"
#define CRED_KEY_SECURITY_LEVEL      "securityLevel"

#define CRED_VALUE_TYPE_DEBUG       "debug"
#define CRED_VALUE_TYPE_RELEASE     "release"


struct NounceOfCertChain {
    uint64_t challenge;
    uint8_t *pbkInfoList;
    uint32_t pbkInfoListLen;
};

struct PbkChain {
    struct DataBuffer src;
    struct DataBuffer sig;
    struct DataBuffer pbk;
    uint32_t algorithm;
};

struct CredData {
    char *credPtr;
    const char *header;
    const char *payload;
    const char *signature;
    const char *attestionInfo;
    struct PbkChain pbkChain[PBK_CHAIN_LEVEL];
};

static int32_t GetSecLevelFromString(const char *data, uint32_t dataLen, uint32_t *securityLevel)
{
    if (data == NULL || dataLen != SEC_LEVEL_STR_LEN) {
        return ERR_INVALID_PARA;
    }
    if (memcmp(data, "SL", SEC_LEVEL_STR_LEN - 1) != 0) {
        return ERR_INVALID_PARA;
    }
    int32_t num = data[SEC_LEVEL_STR_LEN - 1] - '0';
    if (num < CLOUD_CRED_SEC_LEVEL_0 || num > CLOUD_CRED_SEC_LEVEL_MAX) {
        return ERR_INVALID_PARA;
    }
    *securityLevel = num;
    return SUCCESS;
}

static int32_t GetAlgorithmType(const char* data, uint32_t dataLen, uint32_t * algorithm)
{
    if (data == NULL || dataLen == 0) {
        return ERR_INVALID_PARA;
    }
    if (strncmp(data, "SHA384withECDSA", strlen("SHA384withECDSA")) == 0) {
        *algorithm = TYPE_ECDSA_SHA_384;
    } else if (strncmp(data, "SHA256withECDSA", strlen("SHA256withECDSA")) == 0) {
        *algorithm = TYPE_ECDSA_SHA_256;
    } else {
        return ERR_INVALID_PARA;
    }
    return SUCCESS;
}

static int32_t CopyParamDataFromJson(const JsonHandle json, const char *paramKey, char *dest, uint32_t destLen)
{
    const char *tempData = GetJsonFieldString(json, paramKey);
    if (tempData == NULL) {
        return ERR_INVALID_PARA;
    }
    if (strcpy_s(dest, destLen, tempData) != EOK) {
        return ERR_MEMORY_ERR;
    }
    return SUCCESS;
}

static int32_t GetCredPayloadInfo(const char* credPayload, DslmCredInfo *credInfo)
{
    uint8_t *buffer = NULL;
    Base64DecodeApp((uint8_t *)credPayload, &buffer);
    if (buffer == NULL) {
        return ERR_INVALID_PARA;
    }
    JsonHandle json = CreateJson((char*)buffer);
    if (json == NULL) {
        FREE(buffer);
        return ERR_INVALID_PARA;
    }
    FREE(buffer);
    buffer = NULL;

    do {
        credInfo->credType = DEVICE_LEVEL_CRED_TYPE_CRED_CLOUD_WITH_HUKS;

        // get security level
        if (CopyParamDataFromJson(json, CRED_KEY_SECURITY_LEVEL, credInfo->securityLevel, CRED_INFO_LEVEL_LEN) !=
            SUCCESS) {
            SECURITY_LOG_ERROR("get securityLevel failed!");
            break;
        }
        if (GetSecLevelFromString(credInfo->securityLevel, strlen(credInfo->securityLevel), &(credInfo->credLevel)) !=
            SUCCESS) {
            SECURITY_LOG_ERROR("get credLevel failed!");
            break;
        }

        // get type, debug or release
        if (CopyParamDataFromJson(json, CRED_KEY_TYPE, credInfo->type, CRED_INFO_TYPE_LEN) != SUCCESS) {
            SECURITY_LOG_ERROR("get type failed!");
            break;
        }

        // get cred version. The following data is not important, so continue even it fails.
        if (CopyParamDataFromJson(json, CRED_KEY_CRED_VERSION, credInfo->version, CRED_INFO_VERSION_LEN) != SUCCESS) {
            SECURITY_LOG_ERROR("get version failed!");
        }

        // get udid, when type is debug
        if (strncmp(credInfo->type, CRED_VALUE_TYPE_DEBUG, strlen(CRED_VALUE_TYPE_DEBUG)) == 0) {
            if (CopyParamDataFromJson(json, CRED_KEY_UDID, credInfo->udid, CRED_INFO_UDID_LEN) != SUCCESS) {
                SECURITY_LOG_ERROR("get udid failed!");
            }
        }

        // get signTime
        if (CopyParamDataFromJson(json, CRED_KEY_SIGN_TIME, credInfo->signTime, CRED_INFO_SIGNTIME_LEN) != SUCCESS) {
            SECURITY_LOG_ERROR("get signTime failed!");
        }

        // get manufacture
        if (CopyParamDataFromJson(json, CRED_KEY_MANUFACTURE, credInfo->manufacture, CRED_INFO_MANU_LEN) != SUCCESS) {
            SECURITY_LOG_ERROR("get manufacture failed!");
        }

        // get model
        if (CopyParamDataFromJson(json, CRED_KEY_MODEL_NAME, credInfo->model, CRED_INFO_MODEL_LEN) != SUCCESS) {
            SECURITY_LOG_ERROR("get model name failed!");
        }

        // get brand
        if (CopyParamDataFromJson(json, CRED_KEY_BRAND, credInfo->brand, CRED_INFO_BRAND_LEN) != SUCCESS) {
            SECURITY_LOG_ERROR("get brand failed!");
        }

        SECURITY_LOG_DEBUG("ParseCredPayload SUCCESS!");
        DestroyJson(json);
        return SUCCESS;
    } while (0);

    DestroyJson(json);
    return ERR_GET_CLOUD_CRED_INFO;
}

static int32_t GenerateDeviceUdid(const char *manufacture, const char *productModel, const char *serialNum,
    char *udidStr, uint32_t MaxLen)
{
    uint32_t manufactureLen = strlen(manufacture);
    uint32_t productModelLen = strlen(productModel);
    uint32_t serialNumLen = strlen(serialNum);

    uint32_t dataLen = manufactureLen + productModelLen + serialNumLen;
    char *data = (char*)MALLOC(dataLen + 1);

    if (strcat_s(data, dataLen + 1, manufacture) != EOK) {
        return ERR_INVALID_PARA;
    }
    if (strcat_s(data, dataLen + 1, productModel) != EOK) {
        return ERR_INVALID_PARA;
    }
    if (strcat_s(data, dataLen + 1, serialNum) != EOK) {
        return ERR_INVALID_PARA;
    }

    uint8_t hashResult[SHA_256_HASH_RESULT_LEN] = {0};
    CallHashSha256((uint8_t *)data, dataLen, hashResult);

    ByteToHexString(hashResult, SHA_256_HASH_RESULT_LEN, (uint8_t *)udidStr, UDID_STRING_LENGTH);

    return 0;
}

static int32_t CheckCredInfo(const struct DeviceIdentify *device, const char* serialNum, const DslmCredInfo *info)
{
    if (strncmp(info->type, CRED_VALUE_TYPE_DEBUG, strlen(CRED_VALUE_TYPE_DEBUG)) == 0) {
        if (strncmp((char*)device->identity, info->udid, strlen(info->udid)) == 0) {
            return SUCCESS;
        }

        char udidStr[UDID_STRING_LENGTH] = {0};
        GenerateDeviceUdid(info->manufacture, info->model, serialNum, udidStr, UDID_STRING_LENGTH);
        if (strcasecmp(udidStr, info->udid) == 0) {
            return SUCCESS;
        }
        return ERR_CHECK_CRED_INFO;
    }
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

    ret = strcpy_s((char*)nounce->pbkInfoList, strlen(pkInfoListStr) + 1, pkInfoListStr);
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
    if (nounce != NULL && nounce->pbkInfoList != NULL) {
        FREE(nounce->pbkInfoList);
        nounce->pbkInfoList = NULL;
    }
    (void)memset_s(nounce, sizeof(struct NounceOfCertChain), 0, sizeof(struct NounceOfCertChain));
}

static int32_t FindCommonPkInfo(const char* bufferA, const char *bufferB)
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
    uint32_t sizeA = GetJsonFieldJsonArraySize(jsonA);
    uint32_t sizeB = GetJsonFieldJsonArraySize(jsonB);

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

    int32_t ret = FindCommonPkInfo((char *)pbkInfoList, (char*)nounce->pbkInfoList);
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

    int32_t ret = ERR_DEFAULT;
    do {
        ret = ParseNounceOfCertChain(jsonStr, &nounce);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("ParseNounceOfCertChain failed!");
            break;
        }

        ret = GetPkInfoListStr(false, (uint8_t *)device->identity, device->length, &pkInfoListStr);
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

static int32_t ParsePubKeyChain(const char *credAttestionInfo, uint32_t length, struct PbkChain *pbkChain)
{
    uint8_t *buffer = NULL;
    Base64DecodeApp((uint8_t*)credAttestionInfo, &buffer);
    if (buffer == NULL) {
        return ERR_INVALID_PARA;
    }
    JsonHandle json = CreateJson((char *)buffer);
    if (json == NULL) {
        FREE(buffer);
        return ERR_INVALID_PARA;
    }
    FREE(buffer);
    if (GetJsonFieldJsonArraySize(json) != PBK_CHAIN_LEVEL) {
        DestroyJson(json);
        return ERR_JSON_ERR;
    }

    JsonHandle item = NULL;
    const char *srcMsg = NULL;
    const char *sigMsg = NULL;
    const char *pbkMsg = NULL;
    const char *algMsg = NULL;
    for (uint32_t i = 0; i < PBK_CHAIN_LEVEL; i++) {
        item = GetJsonFieldJsonArray(json, PBK_CHAIN_LEVEL - i - 1);
        pbkMsg = srcMsg;
        srcMsg = GetJsonFieldString(item, JSON_KEY_USER_PUBLIC_KEY);
        if (srcMsg == NULL) {
            break;
        }
        sigMsg = GetJsonFieldString(item, JSON_KEY_SIGNATURE);
        if (sigMsg == NULL) {
            break;
        }
        algMsg = GetJsonFieldString(item, JSON_KEY_ALGORITHM);
        if (algMsg == NULL) {
            algMsg = "SHA384withECDSA";
        }
        if (i == 0) {
            pbkMsg = srcMsg;
        }
        pbkChain[i].src.length = Base64UrlDecodeApp((uint8_t *)srcMsg, &(pbkChain[i].src.data));
        if (pbkChain[i].src.data == NULL) {
            break;
        }
        pbkChain[i].sig.length = Base64UrlDecodeApp((uint8_t *)sigMsg, &(pbkChain[i].sig.data));
        if (pbkChain[i].sig.data == NULL) {
            break;
        }
        pbkChain[i].pbk.length = Base64UrlDecodeApp((uint8_t *)pbkMsg, &(pbkChain[i].pbk.data));
        if (pbkChain[i].pbk.data == NULL) {
            break;
        }
        if (GetAlgorithmType(algMsg, strlen(algMsg), &(pbkChain[i].algorithm)) != SUCCESS) {
            SECURITY_LOG_DEBUG("ParsePubKeyChain get type error");
            break;
        }

        if (i == PBK_CHAIN_THIRD_KEY_INDEX) {
            DestroyJson(json);
            SECURITY_LOG_DEBUG("ParsePubKeyChain ok and return");
            return SUCCESS;
        }
    }
    DestroyJson(json);
    return ERR_PARSE_PUBKEY_CHAIN;
}


static int32_t ParseCredData(const char *credStr, struct CredData *credData)
{
    credData->credPtr = (char*)MALLOC(strlen(credStr) + 1);
    if (credData->credPtr == NULL) {
        return ERR_NO_MEMORY;
    }
    if (strcpy_s(credData->credPtr, strlen(credStr) + 1, credStr) != EOK) {
        credData->credPtr = NULL;
        return ERR_MEMORY_ERR;
    }

    char *context = NULL;
    credData->header = strtok_s(credData->credPtr, ".", &context);
    if (context == NULL) {
        return ERR_PARSE_CLOUD_CRED_DATA;
    }
    credData->payload = strtok_s(NULL, ".", &context);
    if (context == NULL) {
        return ERR_PARSE_CLOUD_CRED_DATA;
    }
    credData->signature = strtok_s(NULL, ".", &context);
    if (context == NULL) {
        return ERR_PARSE_CLOUD_CRED_DATA;
    }
    credData->attestionInfo = strtok_s(NULL, ".", &context);
    if (context == NULL) {
        return ERR_PARSE_CLOUD_CRED_DATA;
    }
    
    return ParsePubKeyChain(credData->attestionInfo, strlen(credData->attestionInfo), &credData->pbkChain[0]);
}

static int32_t VerifyCredPubKeyChain(const struct PbkChain *pbkChain)
{
    for (int i = 0; i < 3; i++) {
        if (EcdsaVerify(&(pbkChain[i].src), &(pbkChain[i].sig), &(pbkChain[i].pbk), pbkChain[i].algorithm) != SUCCESS) {
            return ERR_ECC_VERIFY_ERR;
        }
    }
    SECURITY_LOG_ERROR("verifyCredPubKeyChain sucess!");
    return SUCCESS;
}

static int32_t VerifyCredPayload(const char *cred, const struct CredData *credData)
{
    SECURITY_LOG_ERROR("VerifyCredPayload start!");

    uint32_t srcMsgLen = strlen(credData->header) + strlen(credData->payload) + 1;
    char *srcMsg = (char *)MALLOC(srcMsgLen + 1);
    if (srcMsg == NULL) {
        return ERR_NO_MEMORY;
    }
    (void)memset_s(srcMsg, srcMsgLen + 1, 0, srcMsgLen + 1);
    if (memcpy_s(srcMsg, srcMsgLen, cred, srcMsgLen) != EOK) {
        FREE(srcMsg);
        return ERR_MEMORY_ERR;
    }

    struct DataBuffer srcData, sigData, pbkData;
    srcData.data = (uint8_t *)srcMsg;
    srcData.length = strlen(srcMsg);
    SECURITY_LOG_ERROR("src msg = %{public}s", srcMsg);
    SECURITY_LOG_ERROR("src msgLen = %{public}d", srcData.length);
    pbkData.data = credData->pbkChain[PBK_CHAIN_THIRD_KEY_INDEX].src.data;
    pbkData.length = credData->pbkChain[PBK_CHAIN_THIRD_KEY_INDEX].src.length;
    sigData.length = Base64UrlDecodeApp((uint8_t *)credData->signature, &(sigData.data));
    SECURITY_LOG_ERROR("sig msgLen = %{public}d", sigData.length);
    if (sigData.data == NULL) {
        FREE(srcMsg);
        return ERR_MEMORY_ERR;
    }

    int32_t ret = EcdsaVerify(&srcData, &sigData, &pbkData, TYPE_ECDSA_SHA_384);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("EcdsaVerify failed!");
        ret = ERR_ECC_VERIFY_ERR;
    } else {
        SECURITY_LOG_ERROR("EcdsaVerify success!");
        ret = SUCCESS;
    }
    FREE(srcMsg);
    FREE(sigData.data);
    return ret;
}

static void FreeCredData(struct CredData *credData)
{
    if (credData == NULL) {
        return;
    }
    if (credData->credPtr != NULL) {
        FREE(credData->credPtr);
        credData->credPtr = NULL;
    }
    for (uint32_t i = 0; i < PBK_CHAIN_LEVEL; i++) {
        if (credData->pbkChain[i].src.data != NULL) {
            FREE(credData->pbkChain[i].src.data);
            credData->pbkChain[i].src.data = NULL;
        }
        if (credData->pbkChain[i].sig.data != NULL) {
            FREE(credData->pbkChain[i].sig.data);
            credData->pbkChain[i].sig.data = NULL;
        }
        if (credData->pbkChain[i].pbk.data != NULL) {
            FREE(credData->pbkChain[i].pbk.data);
            credData->pbkChain[i].pbk.data = NULL;
        }
    }
    (void)memset_s(credData, sizeof(struct CredData), 0, sizeof(struct CredData));
}

static int32_t VerifyCredData(const char *credStr, DslmCredInfo *credInfo)
{
    struct CredData credData;
    (void)memset_s(&credData, sizeof(struct CredData), 0, sizeof(struct CredData));

    int32_t ret = ERR_DEFAULT;
    do {
        // 1. Parse Cred.
        ret = ParseCredData(credStr, &credData);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("ParseCredData failed!");
            break;
        }

        // 2. Verify public key chain, get root public key.
        ret = VerifyCredPubKeyChain(&credData.pbkChain[0]);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("verifyCredPubKeyChain failed!");
            break;
        }

        // 3. Verify source data by root public key.
        ret = VerifyCredPayload(credStr, &credData);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("verifyCredPayload failed!");
            break;
        }

        // 4. Parse cred payload.
        ret = GetCredPayloadInfo(credData.payload, credInfo);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("verifyCredPayload failed!");
            break;
        }
    } while (0);

    FreeCredData(&credData);
    return SUCCESS;
}

int32_t VerifyOhosDslmCred(const DeviceIdentify *device, uint64_t challenge, const DslmCredBuff *credBuff,
    DslmCredInfo *credInfo)
{
    SECURITY_LOG_INFO("Invoke VerifyOhosDslmCred");
    struct CertChainValidateResult resultInfo;
    InitCertChainValidateResult(&resultInfo, credBuff->credLen);

    int32_t ret = ERR_DEFAULT;
    do {
        // 1. Verify the certificate chain, get data in the certificate chain(nounce + UDID + cred).
        ret = ValidateCertChainAdapter(credBuff->credVal, credBuff->credLen, &resultInfo);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("ValidateCertChainAdapter failed!");
            break;
        }

        // 2. Parses the NOUNCE into CHALLENGE and PK_INFO_LIST, verifies them separtely.
        ret = VerifyNounceOfCertChain((char*)resultInfo.nounce, device, challenge);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("verifyNounceOfCertChain failed!");
            break;
        }

        // 3. The cred content is "<header>.<payload>.<signature>.<attestion>", parse and vefity it.
        ret = VerifyCredData((char*)resultInfo.cred, credInfo);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("VerifyCredData failed!");
            break;
        }

        ret = CheckCredInfo(device, (char*)resultInfo.serialNum, credInfo);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("CheckCredInfo failed!");
            break;
        }
    } while (0);

    DestroyCertChainValidateResult(&resultInfo);
    SECURITY_LOG_INFO("cred level = %{public}d", credInfo->credLevel);
    SECURITY_LOG_INFO("VerifyOhosDslmCred SUCCESS!");
    return ret;
}