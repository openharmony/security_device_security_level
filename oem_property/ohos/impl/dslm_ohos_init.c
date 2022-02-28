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

#include "dslm_ohos_init.h"
#include "dslm_ohos_request.h"
#include "dslm_ohos_verify.h"

#include <string.h>

#include "utils_log.h"

#define DSLM_CRED_STR_LEN_MAX 4096

int32_t InitOhosDslmCred(DslmCredInfo *credInfo)
{
    SECURITY_LOG_INFO("Invoke InitOhosDslmCred");
    char credStr[DSLM_CRED_STR_LEN_MAX] = {0};
    int32_t ret = GetCredFromCurrentDevice(credStr, DSLM_CRED_STR_LEN_MAX);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("InitOhosDslmCred, Read cred data from file failed!");
        return ret;
    }

    ret = VerifyCredData(credStr, credInfo);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("InitOhosDslmCred, VerifyCredData failed!");
        return ret;
    }
    SECURITY_LOG_INFO("InitOhosDslmCred success, self level is %{public}d", credInfo->credLevel);
    return SUCCESS;
}