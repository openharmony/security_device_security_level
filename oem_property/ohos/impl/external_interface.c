#/*
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

#include "device_security_defines.h"
#include "external_interface.h"

#include <securec.h>

#include "device_auth.h"
#include "hks_api.h"
#include "hks_param.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"


char g_keyData[] = "hi_key_data";

char nounceStr[] = "{\"challenge\": \"7856341278563412\",\"pkInfoList\": \"[{\\\"groupId\\\" : \\\"0\\\", \\\"publicKey\\\" : \\\"0\\\"}]\"}";
char credStr[] = 
        "ewogICAgInR5cCI6ICJEU0wiLAp9.eyJzZWN1cml0eUxldmVsIjoiU0w1IiwibWFudWZhY3R1cmUiOiJIVUFXRUkiLCJzaWduVGltZSI6IjIwMjExMjA3MTAzNzQ4IiwibW9kZWwiOiJKQUQtQU4wMCIsInR5cGUiOiJkZWJ1ZyIsInVkaWQiOiJmMzZkOTE4ZDBkYzkyMWM5YTJiMjVkNTI1NzBjYWZlZDcxM2ExMTYzOGY4YzNiOGZiYzI4Nzc5ZmQyMjBlNzgyIiwidmVyc2lvbiI6IjEuMCIsImJyYW5kIjoiSFVBV0VJIn0=.MEUCICg_vkckw64ft9X-K9hP9kNvOPzKqMRuXyFwLAJg9kr2AiEA131hT0GappcsJhFXaMz0tPWIdxciO5d1BBtHmfOpvjs.W3sidXNlclB1YmxpY0tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRTZTRlFzWkZiLWxHbFkwRnpfR2Y2Q3dNWG5zRTRteVBXcUpRR0JPMDU1NjVqRXdSZkZENkIzMG00ZE9iQ2JFUzZ6T2lYek9EUEdBUEpqNkx5UklNdkl3IiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVDRFNBIiwic2lnbmF0dXJlIjoiTUdZQ01RRFM5d255ZFRKdkFTejRhelp5TE9pbHBVQzVFb1B6QlJac0M1OU01N0RyWGluWFVJa2gySFhoNVA0ZTQ0M2daalFDTVFDRng4b0V0a3p5YkotWmw1RUExWS16UWdYQ3MxYXdLS0J4VWJZeG1IUGZTal9HUEQzcmRpaC01WUpwSnF1bUt0VSJ9LHsidXNlclB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFU09kcnY3eXhEaFoxWmRUdDB3QUxCMnhYc0ZsUGV2TkQ0b1lfWE44QWtFTVllWVVyTXBkX1hTQTdlTHo5eVJaa08yX3RoSEx4bUpURGZrOUJFeTlTa0xxUF9xOGZJdzBhSXNBMHI0SlN0djh4YVo0RWxVTGxPV2QxXzF4YV9fdnIiLCJhbGdvcml0aG0iOiJTSEEzODR3aXRoRUNEU0EiLCJzaWduYXR1cmUiOiJNR1VDTUc1LXFFaUtfQ0xIYjNDRXdieU5PbFp4UXpqWGtwc2FnR3FCUkUxZUJjUDBacWhndV9nMEI5dFZhaXg2bE9Pa193SXhBTmdQWFY1dk9EZjFBSTdjckVVajhEMmNQbEVvcEc2LXgyUTM2UUoyMXIwdGlTMmJMT2Y0UE94cHpJN3ZRSVRDaVEifSx7InVzZXJQdWJsaWNLZXkiOiJNSFl3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRW8zQ3VDRUxDN1NpTGFKQ0JDRGRjQ3BldGdJR2toWkxzRl9hMGRkVTFDUjd3NTR6amlzQ1haR191eTZka0ZlZmtlM1Uxb0JpbDR4aTU5TnF5Wk5nUVBsQUhJVUd5a1FxWXhweDVaMGpBQkJKeUFKVWxwdHEzSnVaTlRBN0g5VUs3IiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVDRFNBIiwic2lnbmF0dXJlIjoiTUdZQ01RRF9Sa2ZvRm0tWkJUM05HVzcwZV9BTkh1NDB6TlZNZ1VkbHRObG5TYThtQ1ZpRy1nbkFmNzVTRk11dU80VUxNTXNDTVFET3J4TG1kVTh0OENXLTBkZHUwZVJ4VHJ3Q3JJbVBhcjBqVTBMYkFvVGVkTWF2MzhQQUxrT21NSDBPRE50Z1V3VSJ9XQ==";


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

    char udidStr[68] = { 0 };
    char paramJson[512] = { 0 };
    char *resultBuffer;
    uint32_t resultBufferLen;

    if (memcpy_s(udidStr, 68, udid, udidLen) != EOK) {
        return ERR_MEMORY_ERR;
    }
    int32_t ret = GenerateFuncParamJson(isSelf, udidStr, &paramJson[0], 512);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("GenerateFuncParamJson failed");
        return ret;
    }

    const DeviceGroupManager *interface = GetGmInstance();
    ret = interface->getPkInfoList("dslm_service", paramJson, &resultBuffer, &resultBufferLen);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("GetPkInfoListAdapter failed, continue");
        char *temp = "[{\"groupId\" : \"0\", \"publicKey\" : \"0\"}]";
        resultBuffer = (char*)malloc(strlen(temp) + 1);
        strcpy_s(resultBuffer, strlen(temp) + 1, temp);
        resultBufferLen = strlen(temp);
        //return ret;
    }
    *pkInfoList = (char*)MALLOC(strlen(resultBuffer) + 1);
    if (strcpy_s(*pkInfoList, strlen(resultBuffer) + 1, resultBuffer) != EOK) {
        return ERR_MEMORY_ERR;
    }
    SECURITY_LOG_INFO("pkinfo = %{public}s", *pkInfoList);
    interface->destroyInfo(&resultBuffer);
    return SUCCESS;
}


int DslmCredAttestAdapter(char *nounceStr, char *credStr, uint8_t *certChain, uint32_t *certChainLen)
{
    SECURITY_LOG_INFO("DslmCredAttestAdapter start");
    struct HksParam inputData[] = {
        {.tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = { strlen(nounceStr) + 1, (uint8_t*)nounceStr } }, // 调试，要保证出来的是带结束符的数据
        {.tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = { strlen(credStr) + 1, (uint8_t*)credStr } },
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

    struct HksBlob certChainBlob = { 10240,  certChain};
    struct HksCertChain hksCertChain = { &certChainBlob, 1 };

    const struct HksBlob keyAlias = { sizeof(g_keyData), (uint8_t*)g_keyData };

    int32_t ret = HksAttestKey(&keyAlias, inputParam, &hksCertChain);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_INFO("HksAttestKey ret = %{public}d ", ret);
        return ret;
    }
    *certChainLen = certChainBlob.size;
    SECURITY_LOG_INFO("DslmCredAttestAdapter success, certChainLen =  %{public}d ", *certChainLen);
    return SUCCESS;
}

int ValidateCertChainAdapter(uint8_t *data, uint32_t dataLen, struct CertChainValidateResult *resultInfo)
{
    
    int32_t ret = 0;

    // 证书链数据，数据长度
    struct HksBlob certChain = { dataLen, data };
    resultInfo->nounce = (uint8_t*)malloc(1024);
    resultInfo->cred = (uint8_t*)malloc(10240);
    struct HksBlob challengeBlob = { 1024, resultInfo->nounce};
    struct HksBlob credBlob = { 10240, resultInfo->cred};

    // 验证后返回数据，需要提前分配空间
    struct HksParam tmpParams[] = {
        {.tag = HKS_TAG_ATTESTATION_CHALLENGE, .blob = challengeBlob },
        {.tag = HKS_TAG_ATTESTATION_ID_SEC_LEVEL_INFO, .blob = credBlob },
    };

    struct HksParamSet *resultParam = NULL;
    if (HksInitParamSet(&resultParam) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("ValidateCertChainAdapter error 1");
        return -1;
    }
    if (HksAddParams(resultParam, tmpParams, sizeof(tmpParams) / sizeof(tmpParams[0])) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("ValidateCertChainAdapter error 2");
        return -1;
    }
    if (HksBuildParamSet(&resultParam) != HKS_SUCCESS) {
        SECURITY_LOG_INFO("ValidateCertChainAdapter error 3");    
        return -1;
    }

    ret = HksValidateCertChain(&certChain, resultParam);
    if (ret != HKS_SUCCESS) {
        SECURITY_LOG_INFO("HksValidateCertChain error, ret = %{public}d", ret);
    }
    (void)memcpy_s(resultInfo->nounce, 1024, data, dataLen);
    resultInfo->nounceLen = dataLen;

    (void)memcpy_s(resultInfo->nounce, 1024, (uint8_t*)nounceStr, strlen(nounceStr) + 1);
    resultInfo->nounceLen = dataLen;
    (void)memcpy_s(resultInfo->cred, 10240, (uint8_t*)credStr, strlen(credStr) + 1);
    resultInfo->credLen = strlen(credStr);

    SECURITY_LOG_INFO("resultInfo nounce len = %{public}d", resultInfo->nounceLen);
    SECURITY_LOG_INFO("resultInfo cred len = %{public}d", resultInfo->credLen);
    return ret;
}

void FreeCertChainValidateResult(struct CertChainValidateResult *resultInfo)
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