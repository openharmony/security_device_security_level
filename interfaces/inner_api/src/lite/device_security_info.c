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

#include "device_security_info.h"

#include "ohos_types.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_mutex.h"

#include "device_security_level_defines.h"
#include "device_security_level_proxy.h"

#define DEFAULT_KEEP_LEN 45
#define MAX_KEEP_LEN 300

DslmClientProxy *GetClientProxy(void);
void ReleaseClientProxy(DslmClientProxy *clientProxy);

static inline Mutex *GetMutex(void)
{
    static Mutex mutex = INITED_MUTEX;
    return &mutex;
}

static int32_t RequestDeviceSecurityInfoImpl(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfo **info)
{
    return ERR_IPC_ERR;
}

static int32_t RequestDeviceSecurityInfoAsyncImpl(const DeviceIdentify *identify, const RequestOption *option,
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

    DslmClientProxy *proxy = GetClientProxy();
    if (proxy == NULL) {
        SECURITY_LOG_ERROR("[GetFeatureApi S:%s F:%s]: failed", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
        return ERR_IPC_PROXY_ERR;
    }

    if (proxy->DslmIpcAsyncCall == NULL) {
        SECURITY_LOG_ERROR("proxy has NULL api");
        return ERR_IPC_PROXY_ERR;
    }

    LockMutex(GetMutex());
    uint32_t cookie = ++generated;
    UnlockMutex(GetMutex());
    BOOL result = proxy->DslmIpcAsyncCall((IUnknown *)proxy, *identify, *option, cookie, callback);
    if (result != SUCCESS) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo RequestDeviceSecurityLevel error");
        return result;
    }
    SECURITY_LOG_INFO("GetDeviceSecurityInfo RequestDeviceSecurityLevel success");
    ReleaseClientProxy(proxy);
    
    return SUCCESS;
}

static void FreeDeviceSecurityInfoImpl(DeviceSecurityInfo *info)
{
    if (info != NULL && info->magicNum == SECURITY_MAGIC) {
        info->magicNum = 0;
        FREE(info);
    }
}

static int32_t GetDeviceSecurityLevelValueImpl(const DeviceSecurityInfo *info, int32_t *level)
{
    if (info == NULL || level == NULL) {
        return ERR_INVALID_PARA;
    }
    if (info->magicNum != SECURITY_MAGIC) {
        return ERR_INVALID_PARA;
    }

    *level = (int32_t)(info->level);
    return (int32_t)(info->result);
}

int32_t RequestDeviceSecurityInfo(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfo **info)
{
    return RequestDeviceSecurityInfoImpl(identify, option, info);
}

int32_t RequestDeviceSecurityInfoAsync(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfoCallback callback)
{
    return RequestDeviceSecurityInfoAsyncImpl(identify, option, callback);
}

void FreeDeviceSecurityInfo(DeviceSecurityInfo *info)
{
    return FreeDeviceSecurityInfoImpl(info);
}

int32_t GetDeviceSecurityLevelValue(const DeviceSecurityInfo *info, int32_t *level)
{
    return GetDeviceSecurityLevelValueImpl(info, level);
}
