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

#include "external_interface_adapter.h"
#include "device_security_defines.h"

#include <securec.h>

#include "device_auth.h"
#include "hks_adapter.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_tlv.h"

const char g_dslmKey[] = "dslm_key";

#define HICHAIN_INPUT_PARAM_STRING_LENGTH 512
#define DSLM_CERT_CHAIN_BASE_LENGTH 4096

#define DSLM_INFO_MAX_LEN_UDID 68
#define DSLM_INFO_MAX_LEN_SERIAL 68
#define DSLM_INFO_MAX_LEN_VERSION 128
#define DSLM_INFO_MAX_LEN_CRED 2048
#define DSLM_INFO_MAX_LEN_NONCE 2048

static int32_t GenerateFuncParamJson(bool isSelfPk, const char *udidStr, char *dest, uint32_t destMax);

const char *pkInfoEmpty = "[]";
const char *pkInfoBase = "[{\"groupId\" : \"0\",\"publicKey\" : \"0\"}]";

int32_t GetPkInfoListStr(bool isSelf, const char *udidStr, char **pkInfoList)
{
    SECURITY_LOG_INFO("GetPkInfoListStr start");

    char paramJson[HICHAIN_INPUT_PARAM_STRING_LENGTH] = {0};
    char *resultBuffer = NULL;
    uint32_t resultNum = 0;

    int32_t ret = GenerateFuncParamJson(isSelf, udidStr, &paramJson[0], HICHAIN_INPUT_PARAM_STRING_LENGTH);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("GenerateFuncParamJson failed");
        return ret;
    }

    const DeviceGroupManager *interface = GetGmInstance();
    ret = interface->getPkInfoList(ANY_OS_ACCOUNT, "dslm_service", paramJson, &resultBuffer, &resultNum);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("getPkInfoList failed! ret = %{public}d", ret);
        return ERR_CALL_EXTERNAL_FUNC;
    }

    if (memcmp(resultBuffer, pkInfoEmpty, strlen(pkInfoEmpty)) == 0) {
        SECURITY_LOG_INFO("Current pkInfoList is null");
        *pkInfoList = (char *)MALLOC(strlen(pkInfoBase) + 1);
        if (*pkInfoList == NULL) {

        }
        if (strcpy_s(*pkInfoList, strlen(pkInfoBase) + 1, pkInfoBase) != EOK) {
            ret = ERR_MEMORY_ERR;
        }
    } else {
        *pkInfoList = (char *)MALLOC(strlen(resultBuffer) + 1);
        if (strcpy_s(*pkInfoList, strlen(resultBuffer) + 1, resultBuffer) != EOK) {
            ret = ERR_MEMORY_ERR;
        }
    }
    interface->destroyInfo(&resultBuffer);
    return SUCCESS;
}

int32_t DslmCredAttestAdapter(struct DslmInfoInCertChain *info, uint8_t **certChain, uint32_t *certChainLen)
{
    SECURITY_LOG_INFO("DslmCredAttestAdapter start");

    struct HksBlob keyAlias = {sizeof(g_dslmKey), (uint8_t *)g_dslmKey};
    if (HksGenerateKeyAdapter(&keyAlias) != SUCCESS) {
        SECURITY_LOG_ERROR("HksGenerateKeyAdapter failed!");
        return ERR_HUKS_ERR;
    }
    struct HksParam inputData[] = {
        {.tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = {strlen(info->nonceStr) + 1, (uint8_t *)info->nonceStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = {strlen(info->credStr) + 1, (uint8_t *)info->credStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_UDID, .blob = {strlen(info->udidStr) + 1, (uint8_t *)info->udidStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias},
    };

    struct HksParamSet *inputParam = NULL;
    uint32_t certChainMaxLen = strlen(info->credStr) + strlen(info->nonceStr) + DSLM_CERT_CHAIN_BASE_LENGTH;
    struct HksCertChain *hksCertChain = NULL;
    const struct HksCertChainInitParams certParam = {true, true, true, certChainMaxLen};

    int32_t ret = ConstructHksCertChain(&hksCertChain, &certParam);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("ConstructHksCertChain ret = %{public}d ", ret);
        return ret;
    }
    if (FillHksParamSet(&inputParam, inputData, sizeof(inputData) / sizeof(inputData[0])) != SUCCESS) {
        SECURITY_LOG_ERROR("DslmCredAttestAdapter, FillHksParamSet failed.");
        DestroyHksCertChain(hksCertChain);
        return ERR_CALL_EXTERNAL_FUNC;
    }
    ret = HksAttestKey(&keyAlias, inputParam, hksCertChain);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksAttestKey failed, ret = %{public}d ", ret);
        HksFreeParamSet(&inputParam);
        DestroyHksCertChain(hksCertChain);
        return ERR_CALL_EXTERNAL_FUNC;
    }
    ret = HksCertChainToBuffer(hksCertChain, certChain, certChainLen);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("HksCertChainToHksBlob failed!");
        HksFreeParamSet(&inputParam);
        DestroyHksCertChain(hksCertChain);
        FREE(*certChain);
        *certChain = NULL;
        return ret;
    }
    HksFreeParamSet(&inputParam);
    DestroyHksCertChain(hksCertChain);
    SECURITY_LOG_DEBUG("DslmCredAttestAdapter success, certChainLen = %{public}d ", *certChainLen);
    return SUCCESS;
}

int32_t ValidateCertChainAdapter(const uint8_t *data, uint32_t dataLen, struct DslmInfoInCertChain *resultInfo)
{
    SECURITY_LOG_INFO("ValidateCertChainAdapter start");

    char nonceStr[DSLM_INFO_MAX_LEN_NONCE] = {0};
    char credStr[DSLM_INFO_MAX_LEN_CRED] = {0};
    char udidStr[DSLM_INFO_MAX_LEN_UDID] = {0};
    struct HksParam outputData[] = {
        {.tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = {DSLM_INFO_MAX_LEN_NONCE, (uint8_t *)nonceStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = {DSLM_INFO_MAX_LEN_CRED, (uint8_t *)credStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_UDID, .blob = {DSLM_INFO_MAX_LEN_UDID, (uint8_t *)udidStr}},
    };

    struct HksParamSet *outputParam = NULL;
    struct HksBlob certBlob[CERT_CHAIN_CERT_NUM] = {0};
    struct HksCertChain hksCertChain = {&certBlob[0], CERT_CHAIN_CERT_NUM};

    if (BufferToHksCertChain(data, dataLen, &hksCertChain) != SUCCESS) {
        SECURITY_LOG_ERROR("BufferToHksCertChain failed.");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    if (FillHksParamSet(&outputParam, outputData, sizeof(outputData) / sizeof(outputData[0])) != SUCCESS) {
        SECURITY_LOG_ERROR("ValidateCertChainAdapter, FillHksParamSet failed.");
        return ERR_CALL_EXTERNAL_FUNC;
    }

    if (HksValidateCertChain(&hksCertChain, outputParam) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksValidateCertChain failed!");
        HksFreeParamSet(&outputParam);
        return ERR_CALL_EXTERNAL_FUNC;
    }
    uint32_t cnt = 0;
    if (memcpy_s(resultInfo->nonceStr, DSLM_INFO_MAX_LEN_NONCE, outputParam->params[cnt].blob.data,
        outputParam->params[cnt].blob.size) != EOK) {
        HksFreeParamSet(&outputParam);
        return ERR_MEMORY_ERR;
    }
    cnt++;
    if (memcpy_s(resultInfo->credStr, DSLM_INFO_MAX_LEN_CRED, outputParam->params[cnt].blob.data,
        outputParam->params[cnt].blob.size) != EOK) {
        HksFreeParamSet(&outputParam);
        return ERR_MEMORY_ERR;
    }
    cnt++;
    if (memcpy_s(resultInfo->udidStr, DSLM_INFO_MAX_LEN_UDID, outputParam->params[cnt].blob.data,
        outputParam->params[cnt].blob.size) != EOK) {
        HksFreeParamSet(&outputParam);
        return ERR_MEMORY_ERR;
    }

    SECURITY_LOG_INFO("ValidateCertChainAdapter success!");
    HksFreeParamSet(&outputParam);
    return SUCCESS;
}

int32_t HksAttestIsReadyAdapter(void)
{
    if (HcmIsDeviceKeyExist(NULL) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("Hks attest not ready!");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    return SUCCESS;
}

static int32_t GenerateFuncParamJson(bool isSelfPk, const char *udidStr, char *dest, uint32_t destMax)
{
    JsonHandle json = CreateJson(NULL);
    if (json == NULL) {
        return ERR_INVALID_PARA;
    }

    AddFieldBoolToJson(json, "isSelfPk", isSelfPk);
    AddFieldStringToJson(json, "udid", udidStr);

    char *paramsJsonBuffer = ConvertJsonToString(json);
    if (paramsJsonBuffer == NULL) {
        DestroyJson(json);
        return ERR_MEMORY_ERR;
    }
    DestroyJson(json);
    if (strcpy_s(dest, destMax, paramsJsonBuffer) != EOK) {
        FREE(paramsJsonBuffer);
        paramsJsonBuffer = NULL;
        return ERR_MEMORY_ERR;
    }
    FREE(paramsJsonBuffer);
    paramsJsonBuffer = NULL;
    return SUCCESS;
}

int32_t InitDslmInfoInCertChain(struct DslmInfoInCertChain *saveInfo)
{
    if (saveInfo == NULL) {
        return ERR_INVALID_PARA;
    }
    saveInfo->nonceStr = (char *)MALLOC(DSLM_INFO_MAX_LEN_NONCE);
    if (saveInfo->nonceStr == NULL) {
        return ERR_NO_MEMORY;
    }
    saveInfo->credStr = (char *)MALLOC(DSLM_INFO_MAX_LEN_CRED);
    if (saveInfo->credStr == NULL) {
        FREE(saveInfo->nonceStr);
        saveInfo->nonceStr = NULL;
        return ERR_NO_MEMORY;
    }
    saveInfo->udidStr = (char *)MALLOC(DSLM_INFO_MAX_LEN_UDID);
    if (saveInfo->udidStr == NULL) {
        FREE(saveInfo->nonceStr);
        saveInfo->nonceStr = NULL;
        FREE(saveInfo->credStr);
        saveInfo->credStr = NULL;
        return ERR_NO_MEMORY;
    }
    return SUCCESS;
}

void DestroyDslmInfoInCertChain(struct DslmInfoInCertChain *saveInfo)
{
    if (saveInfo == NULL) {
        return;
    }
    if (saveInfo->nonceStr != NULL) {
        FREE(saveInfo->nonceStr);
        saveInfo->nonceStr = NULL;
    }
    if (saveInfo->credStr != NULL) {
        FREE(saveInfo->credStr);
        saveInfo->credStr = NULL;
    }
    if (saveInfo->udidStr != NULL) {
        FREE(saveInfo->udidStr);
        saveInfo->udidStr = NULL;
    }
    (void)memset_s(saveInfo, sizeof(struct DslmInfoInCertChain), 0, sizeof(struct DslmInfoInCertChain));
}
