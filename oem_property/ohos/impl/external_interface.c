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

#include "external_interface.h"
#include "device_security_defines.h"

#include <securec.h>

#include "device_auth.h"
#include "hks_api.h"
#include "hks_param.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_tlv.h"

char g_keyData[] = "hi_key_data";

#define UDID_STRING_LENGTH 65
#define HICHIAN_INPUT_PARAM_STRING_LENGTH 512

//const static char g_secInfoData[] = "hi_security_level_info";
//const static char g_challengeData[] = "hi_challenge_data";
const static char g_versionData[] = "hi_os_version_data";
const static char g_udidData[] = "hi_udid_data";
const static char g_snData[] = "hi_sn_data";
const static uint32_t g_size = 4096;
#define DSLM_CERT_CHAIN_BASE_LENGTH 4096

//const static struct HksBlob secInfo = { sizeof(g_secInfoData), (uint8_t *)g_secInfoData };
//const static struct HksBlob challenge = { sizeof(g_challengeData), (uint8_t *)g_challengeData };
const static struct HksBlob version = { sizeof(g_versionData), (uint8_t *)g_versionData };
const static struct HksBlob udid = { sizeof(g_udidData), (uint8_t *)g_udidData };
const static struct HksBlob sn = { sizeof(g_snData), (uint8_t *)g_snData };

struct HksTestCertChain {
    bool certChainExist;
    bool certCountValid;
    bool certDataExist;
    uint32_t certDataSize;
};

static int32_t TestGenerateKey(const struct HksBlob *keyAlias)
{
    struct HksParam tmpParams[] = {
        { .tag = HKS_TAG_KEY_STORAGE_FLAG, .uint32Param = HKS_STORAGE_PERSISTENT },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_RSA },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_RSA_KEY_SIZE_2048 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_VERIFY },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_PSS },
        //{ .tag = HKS_TAG_IS_KEY_ALIAS, .boolParam = true },
        { .tag = HKS_TAG_KEY_GENERATE_TYPE, .uint32Param = HKS_KEY_GENERATE_TYPE_DEFAULT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB },
    };
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(paramSet, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0]));
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksAddParams failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksBuildParamSet failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksGenerateKey(keyAlias, paramSet, NULL);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksGenerateKey failed");
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



#define MAX_ENTRY 8
#define TYPE_NOUNCE 0x200
#define TYPE_CERT_BASE 0x100
#define TYPE_CERT_END (TYPE_CERT_BASE + MAX_ENTRY)
#define LIST_MAX_SIZE 8192

static void showData(struct HksCertChain *hksCertChain)
{
    SECURITY_LOG_INFO("hksCertChain->certsCount = %{public}d", hksCertChain->certsCount);
    for (uint32_t i = 0; i < hksCertChain->certsCount; i++) {
        SECURITY_LOG_INFO("blob data Len = %{public}d", hksCertChain->certs[i].size);
/*
        for (uint32_t j = 0; j < hksCertChain->certs[i].size; j++) {
            SECURITY_LOG_INFO("%{public}02x", hksCertChain->certs[i].data[j]);
        }
*/
    }

}

// certChain转blob，需要malloc
static int32_t HksCertChainToHksBlob(struct HksCertChain *hksCertChain, struct HksBlob *hksBlob)
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
    if (Serialize(tlvs, tlvCnt, out, LIST_MAX_SIZE, &(hksBlob->size)) != TLV_OK) {
        FREE(out);
        return ERR_NO_MEMORY;
    }
    hksBlob->data = out;

    return SUCCESS;
}

// blob转为certChain，构造结构体，使其指针对应到blob中对应段。不需要malloc，hksBlob在外面使用完直接释放。
static int32_t HksBlobToHksCertChain(struct HksBlob *hksBlob, struct HksCertChain *hksCertChain)
{
    TlvCommon tlvs[MAX_ENTRY];
    memset_s(&tlvs[0], sizeof(tlvs), 0, sizeof(tlvs));

    uint32_t cnt = 0;
    uint32_t ret = Deserialize(hksBlob->data, hksBlob->size, &tlvs[0], MAX_ENTRY, &cnt);
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

int32_t GetPkInfoListStr(bool isSelf, const uint8_t *udid, uint32_t udidLen, char **pkInfoList)
{
    SECURITY_LOG_INFO("GetPkInfoListStr start");

    char udidStr[UDID_STRING_LENGTH] = {0};
    char paramJson[HICHIAN_INPUT_PARAM_STRING_LENGTH] = {0};
    char resultBuffer[] = "[{\"groupId\" : \"0\",\"publicKey\" : \"0\"}]";

    if (memcpy_s(udidStr, UDID_STRING_LENGTH, udid, udidLen) != EOK) {
        return ERR_MEMORY_ERR;
    }
    int32_t ret = GenerateFuncParamJson(isSelf, udidStr, &paramJson[0], HICHIAN_INPUT_PARAM_STRING_LENGTH);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("GenerateFuncParamJson failed");
        return ret;
    }

    *pkInfoList = (char *)MALLOC(strlen(resultBuffer) + 1);
    if (strcpy_s(*pkInfoList, strlen(resultBuffer) + 1, resultBuffer) != EOK) {
        return ERR_MEMORY_ERR;
    }
    SECURITY_LOG_INFO("pkinfo = %{public}s", *pkInfoList);
    return SUCCESS;
}



int DslmCredAttestAdapter(char *nounceStr, char *credStr, uint8_t **certChain, uint32_t *certChainLen)
{
    SECURITY_LOG_INFO("DslmCredAttestAdapter start");

    char alias[] = "testKey";
    struct HksBlob keyAlias = { sizeof(alias), (uint8_t *)alias };
    if (TestGenerateKey(&keyAlias) != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("TestGenerateKey failed");
    }
    struct HksParam inputData[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = {strlen(credStr) + 1, (uint8_t *)credStr}},
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = {strlen(nounceStr) + 1, (uint8_t *)nounceStr}},
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = version },
        { .tag = HKS_TAG_ATTESTATION_ID_DEVICE, .blob = udid },
        { .tag = HKS_TAG_ATTESTATION_ID_SERIAL, .blob = sn },
        { .tag = HKS_TAG_ATTESTATION_ID_ALIAS, .blob = keyAlias },

    };
    struct HksParamSet *inputParam = NULL;
    if (HksInitParamSet(&inputParam) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("DslmCredAttestAdapter error 1");
        return -1;
    }
    if (HksAddParams(inputParam, inputData, sizeof(inputData) / sizeof(inputData[0])) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("DslmCredAttestAdapter error 2");
        return -1;
    }
    if (HksBuildParamSet(&inputParam) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("DslmCredAttestAdapter error 3");
        return -1;
    }

    uint32_t certChainMaxLen = strlen(nounceStr) + strlen(credStr) + DSLM_CERT_CHAIN_BASE_LENGTH;
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
   showData(hksCertChain);
/*
    ret = HksValidateCertChain(hksCertChain, inputParam);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksValidateCertChain direct failed, ret = %{public}d ", ret);
        //return ret;
    }
*/
    struct HksBlob resultBlob;
    ret = HksCertChainToHksBlob(hksCertChain, &resultBlob);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("HksCertChainToHksBlob failed!");
        return ret;
    }
    *certChain = resultBlob.data;
    *certChainLen = resultBlob.size;
    SECURITY_LOG_INFO("DslmCredAttestAdapter success, certChainLen =  %{public}d ", *certChainLen);
    return SUCCESS;
}

int ValidateCertChainAdapter(uint8_t *data, uint32_t dataLen, struct CertChainValidateResult *resultInfo)
{
    SECURITY_LOG_INFO("ValidateCertChainAdapter start");

    uint8_t *versionData = (uint8_t *)MALLOC(g_size);
    uint8_t *snData = (uint8_t *)MALLOC(g_size);
    uint8_t *udidData = (uint8_t *)MALLOC(g_size);
    struct HksParam outputData[] = {
        { .tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = { resultInfo->credLen, resultInfo->cred } },
        { .tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = { resultInfo->nounceLen, resultInfo->nounce } },
        { .tag = HKS_TAG_ATTESTATION_ID_VERSION_INFO, .blob = { g_size, versionData } },
        { .tag = HKS_TAG_ATTESTATION_ID_UDID, .blob = { g_size, udidData } },
        { .tag = HKS_TAG_ATTESTATION_ID_SERIAL, .blob = { g_size, snData } },
    };
    SECURITY_LOG_INFO("lwk 0");
    struct HksParamSet *outputParam = NULL;
    if (HksInitParamSet(&outputParam) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("lwk 1");
        return -1;
    }
    if (HksAddParams(outputParam, outputData, sizeof(outputData) / sizeof(outputData[0])) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("lwk 2");
        return -1;
    }
    if (HksBuildParamSet(&outputParam) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("lwk 3");
        return -1;
    }

    struct HksBlob certChainBlob = {dataLen, data};
    struct HksCertChain hksCertChain;
    SECURITY_LOG_INFO("lwk 4");
    int32_t ret =  HksBlobToHksCertChain(&certChainBlob, &hksCertChain);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("HksBlobToHksCertChain error, ret = %{public}d", ret);
        return ERR_CALL_EXTERNAL_FUNC;
    }
    SECURITY_LOG_INFO("lwk 5");
    SECURITY_LOG_INFO("lwk %{public}d", hksCertChain.certsCount);
    showData(&hksCertChain);
    ret = HksValidateCertChain(&hksCertChain, outputParam);
    SECURITY_LOG_INFO("lwk 5.5");

    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_ERROR("HksValidateCertChain error, ret = %{public}d", ret);
        return ERR_CALL_EXTERNAL_FUNC;
    }
    // fix
    SECURITY_LOG_INFO("lwk 6");
    resultInfo->nounceLen = strlen((char *)outputParam->params[0].blob.data);
    memcpy_s(resultInfo->nounce, resultInfo->nounceLen + 1, outputParam->params[0].blob.data,
        resultInfo->nounceLen + 1);
    resultInfo->credLen = strlen((char *)outputParam->params[1].blob.data);
    memcpy_s(resultInfo->cred, resultInfo->credLen + 1, outputParam->params[1].blob.data, resultInfo->credLen + 1);

    SECURITY_LOG_INFO("resultInfo nounce len = %{public}d", resultInfo->nounceLen);
    SECURITY_LOG_INFO("resultInfo cred len = %{public}d", resultInfo->credLen);

    SECURITY_LOG_INFO("resultInfo nounce = %{public}s", (char *)resultInfo->nounce);
    SECURITY_LOG_INFO("resultInfo cred = %{public}s", (char *)resultInfo->cred);

    return SUCCESS;
}

void InitCertChainValidateResult(struct CertChainValidateResult *resultInfo, uint32_t maxLen)
{
    (void)memset_s(resultInfo, sizeof(struct CertChainValidateResult), 0, sizeof(struct CertChainValidateResult));
    resultInfo->nounce = (uint8_t *)MALLOC(maxLen);
    resultInfo->nounceLen = maxLen;
    resultInfo->cred = (uint8_t *)MALLOC(maxLen);
    resultInfo->credLen = maxLen;
}

void DestroyCertChainValidateResult(struct CertChainValidateResult *resultInfo)
{
    if (resultInfo == NULL) {
        return;
    }
    if (resultInfo->udid != NULL) {
        FREE(resultInfo->udid);
        resultInfo->udid = NULL;
    }
    if (resultInfo->nounce != NULL) {
        FREE(resultInfo->nounce);
        resultInfo->nounce = NULL;
    }
    if (resultInfo->cred != NULL) {
        FREE(resultInfo->cred);
        resultInfo->cred = NULL;
    }
    if (resultInfo->serialNum != NULL) {
        FREE(resultInfo->serialNum);
        resultInfo->serialNum = NULL;
    }
    (void)memset_s(resultInfo, sizeof(struct CertChainValidateResult), 0, sizeof(struct CertChainValidateResult));
}
