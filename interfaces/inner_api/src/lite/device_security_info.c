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

#include "device_security_level_defines.h"
#ifdef L0_MINI
#include "device_security_level_inner.h"
#else
#include "device_security_level_proxy.h"
#endif

int32_t RequestDeviceSecurityInfoAsyncImpl(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfoCallback callback);

static int32_t RequestDeviceSecurityInfoImpl(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfo **info)
{
    return ERR_IPC_ERR;
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
