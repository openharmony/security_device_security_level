#/*
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
#include "hks_api.h"
#include "hks_param.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_tlv.h"

const char g_dslmKey[] = "dslm_key";

#define DSLM_INFO_MAX_LEN_UDID 68
#define DSLM_INFO_MAX_LEN_SERIAL 68
#define DSLM_INFO_MAX_LEN_VERSION 128
#define DSLM_INFO_MAX_LEN_CRED 2048
#define DSLM_INFO_MAX_LEN_NOUNCE 2048

#define UDID_STRING_LENGTH 65
#define HICHIAN_INPUT_PARAM_STRING_LENGTH 512
#define DSLM_CERT_CHAIN_BASE_LENGTH 4096

#define MAX_ENTRY 8
#define TYPE_NOUNCE 0x200
#define TYPE_CERT_BASE 0x100
#define TYPE_CERT_END (TYPE_CERT_BASE + MAX_ENTRY)
#define LIST_MAX_SIZE 8192

struct HksTestCertChain {
    bool certChainExist;
    bool certCountValid;
    bool certDataExist;
    uint32_t certDataSize;
};

static int32_t HksGenerateKeyAdapter(const struct HksBlob *keyAlias);
static int32_t ConstructDataToCertChain(struct HksCertChain **certChain, const struct HksTestCertChain *certChainParam);
static int32_t HksCertChainToBuffer(struct HksCertChain *hksCertChain, uint8_t **data, uint32_t *dataLen);
static int32_t BufferToHksCertChain(uint8_t *data, uint32_t dataLen, struct HksCertChain *hksCertChain);
static int32_t GenerateFuncParamJson(bool isSelfPk, const char *udidStr, char *dest, uint32_t destMax);

const char *pkInfoEmpty = "[]";
const char *pkInfoBase = "[{\"groupId\" : \"0\",\"publicKey\" : \"0\"}]";

int32_t GetPkInfoListStr(bool isSelf, const char *udidStr, char **pkInfoList)
{
    SECURITY_LOG_INFO("GetPkInfoListStr start");

    char paramJson[HICHIAN_INPUT_PARAM_STRING_LENGTH] = {0};
    char *resultBuffer = NULL;
    uint32_t resultNum = 0;

    int32_t ret = GenerateFuncParamJson(isSelf, udidStr, &paramJson[0], HICHIAN_INPUT_PARAM_STRING_LENGTH);
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
        SECURITY_LOG_INFO("Current pkInfoList is NULL.");
        *pkInfoList = (char *)MALLOC(strlen(pkInfoBase) + 1);
        if (strcpy_s(*pkInfoList, strlen(pkInfoBase) + 1, pkInfoBase) != EOK) {
            ret = ERR_MEMORY_ERR;
        }
    } else {
        *pkInfoList = (char *)MALLOC(strlen(resultBuffer) + 1);
        if (strcpy_s(*pkInfoList, strlen(resultBuffer) + 1, resultBuffer) != EOK) {
            ret = ERR_MEMORY_ERR;
        }
    }
    if (ret == SUCCESS) {
        SECURITY_LOG_INFO("pkinfo = %{public}s", *pkInfoList);
    }
    interface->destroyInfo(&resultBuffer);
    return SUCCESS;
}

int32_t DslmCredAttestAdapter(struct DslmInfoInCertChain *info, uint8_t **certChain, uint32_t *certChainLen)
{
    SECURITY_LOG_INFO("DslmCredAttestAdapter start");

    struct HksBlob keyAlias = {sizeof(g_dslmKey), (uint8_t *)g_dslmKey};
    if (HksGenerateKeyAdapter(&keyAlias) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksGenerateKeyAdapter failed!");
    }
    struct HksParam inputData[] = {
        {.tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = {strlen(info->nounceStr) + 1, (uint8_t *)info->nounceStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = {strlen(info->credStr) + 1, (uint8_t *)info->credStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_UDID, .blob = {strlen(info->udidStr) + 1, (uint8_t *)info->udidStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias},

    };
    struct HksParamSet *inputParam = NULL;
    if (HksInitParamSet(&inputParam) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksInitParamSet failed!");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    if (HksAddParams(inputParam, inputData, sizeof(inputData) / sizeof(inputData[0])) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksAddParams failed!");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    if (HksBuildParamSet(&inputParam) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksBuildParamSet failed!");
        return ERR_CALL_EXTERNAL_FUNC;
    }

    uint32_t certChainMaxLen = strlen(info->credStr) + strlen(info->nounceStr) + DSLM_CERT_CHAIN_BASE_LENGTH;
    struct HksCertChain *hksCertChain = NULL;
    const struct HksTestCertChain certParam = {true, true, true, certChainMaxLen};
    int32_t ret = ConstructDataToCertChain(&hksCertChain, &certParam);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_INFO("ConstructDataToCertChain ret = %{public}d ", ret);
        return ret;
    }

    ret = HksAttestKey(&keyAlias, inputParam, hksCertChain);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksAttestKey failed, ret = %{public}d ", ret);
        return ret;
    }

    ret = HksCertChainToBuffer(hksCertChain, certChain, certChainLen);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("HksCertChainToHksBlob failed!");
        return ret;
    }
    SECURITY_LOG_INFO("DslmCredAttestAdapter success, certChainLen =  %{public}d ", *certChainLen);
    return SUCCESS;
}

int32_t ValidateCertChainAdapter(uint8_t *data, uint32_t dataLen, struct DslmInfoInCertChain *resultInfo)
{
    SECURITY_LOG_INFO("ValidateCertChainAdapter start");

    char nounceStr[DSLM_INFO_MAX_LEN_NOUNCE] = {0};
    char credStr[DSLM_INFO_MAX_LEN_CRED] = {0};
    char udidStr[DSLM_INFO_MAX_LEN_UDID] = {0};
    struct HksParam outputData[] = {
        {.tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = {DSLM_INFO_MAX_LEN_NOUNCE, (uint8_t *)nounceStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = {DSLM_INFO_MAX_LEN_CRED, (uint8_t *)credStr}},
        {.tag = HKS_TAG_ATTESTATION_ID_UDID, .blob = {DSLM_INFO_MAX_LEN_UDID, (uint8_t *)udidStr}},
    };

    struct HksParamSet *outputParam = NULL;
    if (HksInitParamSet(&outputParam) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksInitParamSet failed!");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    if (HksAddParams(outputParam, outputData, sizeof(outputData) / sizeof(outputData[0])) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksAddParams failed!");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    if (HksBuildParamSet(&outputParam) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksBuildParamSet failed!");
        return ERR_CALL_EXTERNAL_FUNC;
    }

    struct HksBlob certBlob[4] = {0};
    struct HksCertChain hksCertChain = {&certBlob[0], 4};

    int32_t ret = BufferToHksCertChain(data, dataLen, &hksCertChain);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("HksBlobToHksCertChain error, ret = %{public}d", ret);
        return ERR_CALL_EXTERNAL_FUNC;
    }

    ret = HksValidateCertChain(&hksCertChain, outputParam);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksValidateCertChain error, ret = %{public}d", ret);
        return ERR_CALL_EXTERNAL_FUNC;
    }
    if (memcpy_s(resultInfo->nounceStr, DSLM_INFO_MAX_LEN_NOUNCE, outputParam->params[0].blob.data,
            outputParam->params[0].blob.size) != EOK) {
        SECURITY_LOG_INFO("memcpy_s error 1!  %{public}d", outputParam->params[0].blob.size);
        return ERR_MEMORY_ERR;
    }
    if (memcpy_s(resultInfo->credStr, DSLM_INFO_MAX_LEN_CRED, outputParam->params[1].blob.data,
            outputParam->params[1].blob.size) != EOK) {
        SECURITY_LOG_INFO("memcpy_s error 2!  %{public}d", outputParam->params[1].blob.size);
        return ERR_MEMORY_ERR;
    }
    if (memcpy_s(resultInfo->udidStr, DSLM_INFO_MAX_LEN_UDID, outputParam->params[2].blob.data,
            outputParam->params[2].blob.size) != EOK) {
        SECURITY_LOG_INFO("memcpy_s error 3!  %{public}d", outputParam->params[2].blob.size);
        return ERR_MEMORY_ERR;
    }

    SECURITY_LOG_INFO("ValidateCertChainAdapter success!");
    return SUCCESS;
}

int32_t HksAttestIsReadyAdapter()
{
    if (HksIsAttestReady() != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("Hks attest not ready!");
        return ERR_CALL_EXTERNAL_FUNC;
    }
    return SUCCESS;
}

static int32_t HksGenerateKeyAdapter(const struct HksBlob *keyAlias)
{
    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT},
        {.tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA},
        {.tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048},
        {.tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY},
        {.tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256},
        {.tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS},
        {.tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT},
        {.tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB},
    };
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksInitParamSet failed!");
        return ret;
    }

    ret = HksAddParams(paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksAddParams failed!");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksBuildParamSet failed!");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksGenerateKey(keyAlias, paramSet, NULL);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksGenerateKey failed!");
    }
    HksFreeParamSet(&paramSet);
    return ret;
}

static int32_t ConstructDataToCertChain(struct HksCertChain **certChain, const struct HksTestCertChain *certChainParam)
{
    if (!certChainParam->certChainExist) {
        return 0;
    }
    *certChain = (struct HksCertChain *)MALLOC(sizeof(struct HksCertChain));
    if (*certChain == NULL) {
        SECURITY_LOG_ERROR("malloc fail");
        return HKS_ERROR_MALLOC_FAIL;
    }
    if (!certChainParam->certCountValid) {
        (*certChain)->certsCount = 0;
        return 0;
    }
    (*certChain)->certsCount = 4;
    if (!certChainParam->certDataExist) {
        (*certChain)->certs = NULL;
        return 0;
    }
    (*certChain)->certs = (struct HksBlob *)MALLOC(sizeof(struct HksBlob) * ((*certChain)->certsCount));
    for (uint32_t i = 0; i < (*certChain)->certsCount; i++) {
        (*certChain)->certs[i].size = certChainParam->certDataSize;
        (*certChain)->certs[i].data = (uint8_t *)MALLOC((*certChain)->certs[i].size);
        if ((*certChain)->certs[i].data == NULL) {
            SECURITY_LOG_ERROR("malloc fail");
            return HKS_ERROR_MALLOC_FAIL;
        }
        memset_s((*certChain)->certs[i].data, certChainParam->certDataSize, 0, certChainParam->certDataSize);
    }
    return 0;
}

// certChain转blob，需要malloc
static int32_t HksCertChainToBuffer(struct HksCertChain *hksCertChain, uint8_t **data, uint32_t *dataLen)
{
    TlvCommon tlvs[MAX_ENTRY];
    memset_s(&tlvs[0], sizeof(tlvs), 0, sizeof(tlvs));
    uint8_t lwk = 100;

    uint32_t tlvCnt = 0;
    tlvs[tlvCnt].tag = TYPE_NOUNCE;
    tlvs[tlvCnt].len = 100;
    tlvs[tlvCnt].value = &lwk;

    for (uint32_t i = 0; i < hksCertChain->certsCount; i++) {
        tlvs[tlvCnt].tag = TYPE_CERT_BASE + 1;
        tlvs[tlvCnt].len = hksCertChain->certs[i].size;
        tlvs[tlvCnt].value = hksCertChain->certs[i].data;
        tlvCnt++;
    }

    uint8_t *out = MALLOC(LIST_MAX_SIZE);
    if (out == NULL) {
        return ERR_NO_MEMORY;
    }
    memset_s(out, LIST_MAX_SIZE, 0, LIST_MAX_SIZE);
    if (Serialize(tlvs, tlvCnt, out, LIST_MAX_SIZE, dataLen) != TLV_OK) {
        FREE(out);
        return ERR_NO_MEMORY;
    }

    *data = out;
    return SUCCESS;
}

// blob转为certChain，构造结构体，使其指针对应到blob中对应段。不需要malloc，hksBlob在外面使用完直接释放。
static int32_t BufferToHksCertChain(uint8_t *data, uint32_t dataLen, struct HksCertChain *hksCertChain)
{
    TlvCommon tlvs[MAX_ENTRY];
    memset_s(&tlvs[0], sizeof(tlvs), 0, sizeof(tlvs));

    uint32_t cnt = 0;
    uint32_t ret = Deserialize(data, dataLen, &tlvs[0], MAX_ENTRY, &cnt);
    if (ret != TLV_OK || cnt == 0) {
        return ERR_INVALID_PARA;
    }
    uint32_t certCnt = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        if ((tlvs[i].tag >= TYPE_CERT_BASE) && (tlvs[i].tag <= TYPE_CERT_END)) {
            if (certCnt >= MAX_ENTRY) {
                return ERR_HUKS_ERR;
            }
            hksCertChain->certs[certCnt].data = tlvs[i].value;
            hksCertChain->certs[certCnt].size = tlvs[i].len;
            certCnt++;
        }
    }
    hksCertChain->certsCount = certCnt;
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
    saveInfo->nounceStr = (char *)MALLOC(DSLM_INFO_MAX_LEN_NOUNCE);
    if (saveInfo->nounceStr == NULL) {
        return ERR_NO_MEMORY;
    }
    saveInfo->credStr = (char *)MALLOC(DSLM_INFO_MAX_LEN_CRED);
    if (saveInfo->credStr == NULL) {
        return ERR_NO_MEMORY;
    }
    saveInfo->udidStr = (char *)MALLOC(DSLM_INFO_MAX_LEN_UDID);
    if (saveInfo->udidStr == NULL) {
        return ERR_NO_MEMORY;
    }
    return SUCCESS;
}

void DestroyDslmInfoInCertChain(struct DslmInfoInCertChain *saveInfo)
{
    if (saveInfo == NULL) {
        return;
    }
    if (saveInfo->nounceStr != NULL) {
        FREE(saveInfo->nounceStr);
        saveInfo->nounceStr = NULL;
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
