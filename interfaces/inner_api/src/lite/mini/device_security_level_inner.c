/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "device_security_level_inner.h"

#include "ohos_types.h"
#include "utils_log.h"
#include "utils_mutex.h"

static inline Mutex *GetMutex(void)
{
    static Mutex mutex = INITED_MUTEX;
    return &mutex;
}

static DslmFeatureApi *GetInnerApi(void)
{
    DslmFeatureApi *api = NULL;
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
    if (iUnknown == NULL) {
        SECURITY_LOG_ERROR("iUnknown is NULL");
        return NULL;
    }

    int32_t result = iUnknown->QueryInterface(iUnknown, DEFAULT_VERSION, (void **)&api);
    if (result != 0 || api == NULL) {
        SECURITY_LOG_ERROR("QueryInterface failed");
        return NULL;
    }
    return api;
}

static void ReleaseInnerApi(DslmFeatureApi *innerApi)
{
    if (innerApi == NULL) {
        return;
    }

    int32_t result = innerApi->Release((IUnknown *)innerApi);
    SECURITY_LOG_INFO("[Release api S:%s, F:%s]: ret:%d", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE, result);
}

int32_t RequestDeviceSecurityInfoAsyncImpl(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfoCallback callback)
{
    static uint32_t generated = 0;
    if (identify == NULL || callback == NULL) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo input error");
        return ERR_INVALID_PARA;
    }

    static RequestOption defaultOption = {0, DEFAULT_KEEP_LEN, 0};
    if (option == NULL) {
        option = &defaultOption;
    }
    if (option->timeout > MAX_KEEP_LEN) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo input error, timeout too long");
        return ERR_INVALID_PARA;
    }

    LockMutex(GetMutex());
    uint32_t cookie = ++generated;
    UnlockMutex(GetMutex());
    DslmFeatureApi *api = GetInnerApi();
    if (api == NULL) {
        SECURITY_LOG_ERROR("[GetFeatureApi S:%s F:%s]: failed", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
        return ERR_IPC_ERR;
    }
    if (api->DslmGetDeviceSecurityLevel == NULL) {
        SECURITY_LOG_ERROR("empty api");
        return ERR_IPC_ERR;
    }

    DslmAsyncCallParams params = { identify, option, cookie};
    BOOL result = api->DslmGetDeviceSecurityLevel((IUnknown *)api, &params, callback);
    if (result != SUCCESS) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo RequestDeviceSecurityLevel error");
        return result;
    }
    SECURITY_LOG_INFO("GetDeviceSecurityInfo RequestDeviceSecurityLevel success");
    ReleaseInnerApi(api);
    return SUCCESS;
}