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

#include "dslm_ohos_request.h"
#include "external_interface.h"

#include "utils_log.h"
#include <securec.h>
#include <string.h>

#include "utils_json.h"
#include "utils_hexstring.h"
#include "utils_mem.h"

static int32_t TransToJsonBuffer(uint64_t challenge, const uint8_t *pbkBuffer, uint32_t pbkBufferLen,
    uint8_t **jsonBuffer, uint32_t *jsonBufferLen);

int32_t RequestOhosDslmCred(const DeviceIdentify *device, const RequestObject *obj, DslmCredBuff **credBuff)
{
    SECURITY_LOG_INFO("lwk Invoke RequestOhosDslmCred");
    static const char *credStr =
        "ewogICAgInR5cCI6ICJEU0wiLAp9.eyJzZWN1cml0eUxldmVsIjoiU0w1IiwibWFudWZhY3R1cmUiOiJIVUFXRUkiLCJzaWduVGltZSI6IjIwMjExMjA3MTAzNzQ4IiwibW9kZWwiOiJKQUQtQU4wMCIsInR5cGUiOiJkZWJ1ZyIsInVkaWQiOiJmMzZkOTE4ZDBkYzkyMWM5YTJiMjVkNTI1NzBjYWZlZDcxM2ExMTYzOGY4YzNiOGZiYzI4Nzc5ZmQyMjBlNzgyIiwidmVyc2lvbiI6IjEuMCIsImJyYW5kIjoiSFVBV0VJIn0=.MEUCICg_vkckw64ft9X-K9hP9kNvOPzKqMRuXyFwLAJg9kr2AiEA131hT0GappcsJhFXaMz0tPWIdxciO5d1BBtHmfOpvjs.W3sidXNlclB1YmxpY0tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRTZTRlFzWkZiLWxHbFkwRnpfR2Y2Q3dNWG5zRTRteVBXcUpRR0JPMDU1NjVqRXdSZkZENkIzMG00ZE9iQ2JFUzZ6T2lYek9EUEdBUEpqNkx5UklNdkl3IiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVDRFNBIiwic2lnbmF0dXJlIjoiTUdZQ01RRFM5d255ZFRKdkFTejRhelp5TE9pbHBVQzVFb1B6QlJac0M1OU01N0RyWGluWFVJa2gySFhoNVA0ZTQ0M2daalFDTVFDRng4b0V0a3p5YkotWmw1RUExWS16UWdYQ3MxYXdLS0J4VWJZeG1IUGZTal9HUEQzcmRpaC01WUpwSnF1bUt0VSJ9LHsidXNlclB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFU09kcnY3eXhEaFoxWmRUdDB3QUxCMnhYc0ZsUGV2TkQ0b1lfWE44QWtFTVllWVVyTXBkX1hTQTdlTHo5eVJaa08yX3RoSEx4bUpURGZrOUJFeTlTa0xxUF9xOGZJdzBhSXNBMHI0SlN0djh4YVo0RWxVTGxPV2QxXzF4YV9fdnIiLCJhbGdvcml0aG0iOiJTSEEzODR3aXRoRUNEU0EiLCJzaWduYXR1cmUiOiJNR1VDTUc1LXFFaUtfQ0xIYjNDRXdieU5PbFp4UXpqWGtwc2FnR3FCUkUxZUJjUDBacWhndV9nMEI5dFZhaXg2bE9Pa193SXhBTmdQWFY1dk9EZjFBSTdjckVVajhEMmNQbEVvcEc2LXgyUTM2UUoyMXIwdGlTMmJMT2Y0UE94cHpJN3ZRSVRDaVEifSx7InVzZXJQdWJsaWNLZXkiOiJNSFl3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRW8zQ3VDRUxDN1NpTGFKQ0JDRGRjQ3BldGdJR2toWkxzRl9hMGRkVTFDUjd3NTR6amlzQ1haR191eTZka0ZlZmtlM1Uxb0JpbDR4aTU5TnF5Wk5nUVBsQUhJVUd5a1FxWXhweDVaMGpBQkJKeUFKVWxwdHEzSnVaTlRBN0g5VUs3IiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVDRFNBIiwic2lnbmF0dXJlIjoiTUdZQ01RRF9Sa2ZvRm0tWkJUM05HVzcwZV9BTkh1NDB6TlZNZ1VkbHRObG5TYThtQ1ZpRy1nbkFmNzVTRk11dU80VUxNTXNDTVFET3J4TG1kVTh0OENXLTBkZHUwZVJ4VHJ3Q3JJbVBhcjBqVTBMYkFvVGVkTWF2MzhQQUxrT21NSDBPRE50Z1V3VSJ9XQ==";

    uint8_t *certChain = (uint8_t*)malloc(10240);
    uint32_t certChainLen = 0;
    uint8_t *pkInfoListBuf = NULL;
    uint32_t pkInfoListBufLen = 0;
    uint8_t *nounceBuffer = NULL;
    uint32_t nounceBufferLen = 0;

    int32_t ret = -1;
    ret = GetPkInfoListBuffer(true, (uint8_t*)device->identity, device->length, &pkInfoListBuf, &pkInfoListBufLen);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("lwk GetPkInfoListBuffer failed");
        return ret;
    }

    ret = TransToJsonBuffer(obj->challenge, pkInfoListBuf, pkInfoListBufLen, &nounceBuffer, &nounceBufferLen);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("lwk TransToJsonBuffer failed");
        return ret;
    }
 SECURITY_LOG_INFO("lwk TransToJsonBuffer result = %{public}s", (char*)nounceBuffer);
    ret = DslmCredAttestAdapter(nounceBuffer, nounceBufferLen, (uint8_t*)credStr, strlen(credStr), certChain, &certChainLen, 10240);
    if (ret != SUCCESS) {
        SECURITY_LOG_INFO("lwk DslmCredAttestAdapter failed");
        return ret;
    }
    SECURITY_LOG_INFO("lwk DslmCredAttestAdapter success, len = %{public}d", certChainLen);
    DslmCredBuff *out = CreateDslmCred(CRED_TYPE_STANDARD, certChainLen, (uint8_t *)certChain);
    if (out == NULL) {
        return ERR_MEMORY_ERR;
    }
    *credBuff = out;
    return SUCCESS;
}



static int32_t TransToJsonBuffer(uint64_t challenge, const uint8_t *pbkBuffer, uint32_t pbkBufferLen,
    uint8_t **jsonBuffer, uint32_t *jsonBufferLen)
{
    if (pbkBuffer == NULL || pbkBufferLen == 0) {
        return ERR_INVALID_PARA;
    }
    JsonHandle json = CreateJson(NULL);
    if (json == NULL) {
        return ERR_INVALID_PARA;
    }

    // add challenge
    char challengeStr[32] = { 0 };
    char *saveData = &challengeStr[0];
    ByteToHexString((uint8_t *)&challenge, sizeof(challenge), (uint8_t *)saveData, 32);
    AddFieldStringToJson(json, "challenge", saveData);

    // add pkInfoList
    AddFieldStringToJson(json, "pkInfoList", (char *)pbkBuffer);

    // tran to json
    *jsonBuffer = (uint8_t *)ConvertJsonToString(json);
    if (*jsonBuffer == NULL) {
        DestroyJson(json);
        return ERR_JSON_ERR;
    }
    *jsonBufferLen = strlen((char*)*jsonBuffer) + 1;
    DestroyJson(json);
    return SUCCESS;
}



