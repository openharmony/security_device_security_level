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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "securec.h"

#include "external_interface_adapter.h"
#include "utils_hexstring.h"
#include "utils_json.h"
#include "utils_log.h"
#include "utils_mem.h"

#define DSLM_CRED_CFG_FILE_POSITION "/system/etc/dslm_finger.cfg"
#define DSLM_CRED_STR_LEN_MAX 4096
#define CHALLENGE_STRING_LENGTH 32
#define UDID_STRING_LENGTH 65

#define DEVAUTH_JSON_KEY_CHALLENGE "challenge"
#define DEVAUTH_JSON_KEY_PK_INFO_LIST "pkInfoList"

static int32_t TransToJsonStr(const char *challengeStr, const char *pkInfoListStr, char **nonceStr)
{
    DslmJsonHandle json = DslmCreateJson(NULL);
    if (json == NULL) {
        return ERR_INVALID_PARA;
    }

    // add challenge
    DslmAddFieldStringToJson(json, DEVAUTH_JSON_KEY_CHALLENGE, challengeStr);

    // add pkInfoList
    DslmAddFieldStringToJson(json, DEVAUTH_JSON_KEY_PK_INFO_LIST, pkInfoListStr);

    // tran to json
    *nonceStr = DslmConvertJsonToString(json);
    if (*nonceStr == NULL) {
        DslmDestroyJson(json);
        return ERR_JSON_ERR;
    }
    DslmDestroyJson(json);
    return SUCCESS;
}

static int32_t GenerateDslmCertChain(const DeviceIdentify *device, const RequestObject *obj, char *credStr,
    uint8_t **certChain, uint32_t *certChainLen)
{
    char *pkInfoListStr = NULL;
    char *nonceStr = NULL;
    char challengeStr[CHALLENGE_STRING_LENGTH] = {0};
    DslmByteToHexString((uint8_t *)&(obj->challenge), sizeof(obj->challenge), (uint8_t *)challengeStr,
        CHALLENGE_STRING_LENGTH);
    char udidStr[UDID_STRING_LENGTH] = {0};
    if (memcpy_s(udidStr, UDID_STRING_LENGTH, device->identity, device->length) != EOK) {
        return ERR_MEMORY_ERR;
    }
    int32_t ret = ERR_DEFAULT;
    do {
        ret = GetPkInfoListStr(true, udidStr, &pkInfoListStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("GetPkInfoListStr failed");
            break;
        }

        ret = TransToJsonStr(challengeStr, pkInfoListStr, &nonceStr);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("TransToJsonStr failed");
            break;
        }
        struct DslmInfoInCertChain saveInfo = {.credStr = credStr, .nonceStr = nonceStr, .udidStr = udidStr};
        ret = DslmCredAttestAdapter(&saveInfo, certChain, certChainLen);
        if (ret != SUCCESS) {
            SECURITY_LOG_ERROR("DslmCredAttestAdapter failed");
            break;
        }
    } while (0);

    if (pkInfoListStr != NULL) {
        FREE(pkInfoListStr);
    }
    if (nonceStr != NULL) {
        FREE(nonceStr);
    }
    return ret;
}

static int32_t SelectDslmCredType(const DeviceIdentify *device, const RequestObject *obj, uint32_t *type)
{
    (void)device;
    (void)obj;
    if (HksAttestIsReadyAdapter() != SUCCESS) {
#ifdef L0_MINI
        *type = CRED_TYPE_MINI;
#else
        *type = CRED_TYPE_SMALL;
#endif
    } else {
        *type = CRED_TYPE_STANDARD;
    }
    return SUCCESS;
}

static int32_t RequestLiteDslmCred(uint32_t credType, uint8_t *data, uint32_t dataLen, DslmCredBuff **credBuff)
{
    DslmCredBuff *out = CreateDslmCred(credType, dataLen, data);
    if (out == NULL) {
        SECURITY_LOG_ERROR("CreateDslmCred failed");
        return ERR_MEMORY_ERR;
    }
    *credBuff = out;
    SECURITY_LOG_INFO("success");
    return SUCCESS;
}

static int32_t RequestStandardDslmCred(const DeviceIdentify *device, const RequestObject *obj, char *credStr,
    DslmCredBuff **credBuff)
{
    uint8_t *certChain = NULL;
    uint32_t certChainLen = 0;
    int32_t ret = GenerateDslmCertChain(device, obj, credStr, &certChain, &certChainLen);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("GenerateDslmCertChain failed");
        return ret;
    }
    DslmCredBuff *out = CreateDslmCred(CRED_TYPE_STANDARD, certChainLen, certChain);
    if (out == NULL) {
        FREE(certChain);
        SECURITY_LOG_ERROR("CreateDslmCred failed");
        return ERR_MEMORY_ERR;
    }
    FREE(certChain);
    *credBuff = out;
    SECURITY_LOG_INFO("success");
    return SUCCESS;
}

#ifndef L0_MINI
int32_t GetCredFromCurrentDevice(char *credStr, uint32_t maxLen)
{
    if (credStr == NULL || maxLen == 0) {
        return ERR_INVALID_PARA;
    }
    FILE *fp = NULL;
    fp = fopen(DSLM_CRED_CFG_FILE_POSITION, "r");
    if (fp == NULL) {
        SECURITY_LOG_ERROR("fopen cred file failed");
        return ERR_INVALID_PARA;
    }

    int32_t ret = fscanf_s(fp, "%s", credStr, maxLen);
    if (ret <= 0) {
        SECURITY_LOG_ERROR("fscanf_s cred file failed");
        ret = ERR_INVALID_PARA;
    } else {
        ret = SUCCESS;
    }

    if (fclose(fp) != 0) {
        SECURITY_LOG_ERROR("fclose cred file failed");
        ret = ERR_INVALID_PARA;
    }
    return ret;
}
#else
int32_t GetCredFromCurrentDevice(char *credStr, uint32_t maxLen)
{
    if (credStr == NULL || maxLen == 0) {
        return ERR_INVALID_PARA;
    }
    const char cred[] =
        "eyJ0eXAiOiAiRFNMIn0=."
        "eyJ0eXBlIjogImRlYnVnIiwgIm1hbnVmYWN0dXJlIjogIk9IT1MiLCAiYnJhbmQiOiAiT0hPUyIsICJtb2RlbCI6ICJPSE9TIiwgInNvZnR3YX"
        "JlVmVyc2lvbiI6ICIzLjAuMCIsICJzZWN1cml0eUxldmVsIjogIlNMMSIsICJzaWduVGltZSI6ICIyMDIyMDgyMjExNTcyMCIsICJ2ZXJzaW9u"
        "IjogIjEuMC4xIn0=.MGQCMFxmouOZBmCbs4d0RvTdWOYwSsXyDwwbaNXNMadroqmACGdXMYyC0J0/uza9BBkR/"
        "gIwB5Zumkm4EhfvHocEWj4gW+aDcanBMIA73onLZBYqVOseXaMjz9O//"
        "HOXN7Y6r0T0."
        "W3sidXNlclB1YmxpY0tleSI6ICJNSG93RkFZSEtvWkl6ajBDQVFZSkt5UURBd0lJQVFFTEEySUFCR3VNaFVGRm5sUGtVd013dDhpQ3JPRUdEL0"
        "xRaU1FMmZ6TE0rc2RaRXhJOWQxN0RsWGhJU2YrWnRzeFROVDR0NDNDSW1YbTltenJMOTVtOCtKWEJZSGgza0lTZElnZHAxdVRmbEZIVjBYZm1p"
        "YngrMlRMTG5QY3VXMFBWTXhKODZnPT0iLCAic2lnbmF0dXJlIjogIk1HUUNNQ0Z4VGxldjhXVjZkNktueFpya3pRbGY3SE85Tm1Ua3NXeTV4aF"
        "VOcjlMamlMcnU3dEY1emYrMEJZeG52WXgybVFJd2NhenVtd0dsaGxORHgrZHJ0Z0JzSHFLckdqcWRENDNTbDkzR3B3NE83Uk5RUzJQdng4SmtK"
        "YnRFVWVyZHYvNVMifSwgeyJ1c2VyUHVibGljS2V5IjogIk1Ib3dGQVlIS29aSXpqMENBUVlKS3lRREF3SUlBUUVMQTJJQUJFQkFGWTkrM0RaTH"
        "M4TnRaRHVsZHRwQmp1alB2d2llUDlUdk1PWFZrNWZ2SkhFUXY2WERlbEdPNGRnUVozNlVKQ2lVd1UyL3JLckNrenFvS0ttaXNNa0Y2aFFnblZF"
        "Z3l3a3haV24zaHFjengzcDdzamF2S3lSYnRXVW5XdmtTV2c9PSIsICJzaWduYXR1cmUiOiAiTUdRQ01GU2JHMzdMc0dzRkpLZ1lDVUR0S3BtQ3"
        "FVRHc1ck1MVkhjQ3ZtaDVhcVhrQmQ2RzlzUDZGd0RqbmdYeEtsQ1RMZ0l3ZHV4dEg0YUQ5RjN3T0tQNnZJM1FvcVNneWJIMkZjdytFY3o2Mk03"
        "T0RtN0p3RWRmZXowSkJ1Y0dKM0hKZXVVVyJ9LCB7InVzZXJQdWJsaWNLZXkiOiAiTUhvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUxBMk"
        "lBQkRFMHNPMUVWcXViUHMxbDNadmpBTE5xRkcrUlBIei9NK3RPeUN6cTJuNUFNRnUrMWxsUEFhVEdYYzQwTy9uTGluei84emZaNHREQWlUb3NB"
        "UmlKK20zckVWTUZrQitmbnh5SEFDc2UrYWpHdmZxZ2F2ajlGTXNIYjJMRVpQZmkrdz09IiwgInNpZ25hdHVyZSI6ICJNR01DTUV0dDc1VG0wUm"
        "dtYlkvb2Vpb0Y3cHc2K28vZEJmWTFCVVR0RHlVbjFyWjltTW1NWGxyQ0ovaGFTc25oSG12d2h3SXZmYTBTZ0gzWENBbURUWm0xMnpTUHc4b1lI"
        "L3QvNXF0S0tHdlpFZWJmSldIQVE5MFpnblhUdWNOR0FQY05BOEk9In1d";
    int32_t ret = sscanf_s(cred, "%s", credStr, maxLen);
    if (ret <= 0) {
        SECURITY_LOG_ERROR("sscanf_s cred file failed, ret = %d", ret);
        ret = ERR_INVALID_PARA;
    } else {
        ret = SUCCESS;
    }
    return ret;
}
#endif

int32_t RequestOhosDslmCred(const DeviceIdentify *device, const RequestObject *obj, DslmCredBuff **credBuff)
{
    SECURITY_LOG_INFO("start");
    uint32_t credType = 0;
    char credStr[DSLM_CRED_STR_LEN_MAX] = {0};
    int32_t ret = GetCredFromCurrentDevice(credStr, DSLM_CRED_STR_LEN_MAX);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("read cred data from file failed");
        return ret;
    }
    ret = SelectDslmCredType(device, obj, &credType);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("SelectDslmCredType failed");
        return ret;
    }
    switch (credType) {
        case CRED_TYPE_STANDARD:
            return RequestStandardDslmCred(device, obj, credStr, credBuff);
        case CRED_TYPE_SMALL:
        case CRED_TYPE_MINI:
            return RequestLiteDslmCred(credType, (uint8_t *)credStr, strlen(credStr) + 1, credBuff);
        default:
            SECURITY_LOG_ERROR("invalid cred type");
            return ERR_INVALID_PARA;
    }

    return SUCCESS;
}
