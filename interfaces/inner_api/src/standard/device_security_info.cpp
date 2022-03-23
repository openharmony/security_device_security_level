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

#include <future>

#include "hilog/log.h"
#include "iservice_registry.h"

#include "device_security_level_callback_helper.h"
#include "device_security_level_callback_stub.h"
#include "device_security_level_defines.h"
#include "device_security_level_proxy.h"

using namespace OHOS::HiviewDFX;
using namespace OHOS::Security::DeviceSecurityLevel;

static int32_t RequestDeviceSecurityInfoAsyncImpl(const DeviceIdentify *identify, const RequestOption *option,
    ResultCallback callback)
{
    if (identify == nullptr || callback == nullptr) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo input error.");
        return ERR_INVALID_PARA;
    }

    constexpr uint32_t DEAFULT_KEEP_LEN = 45;
    constexpr uint32_t MAX_KEEP_LEN = 300;
    static RequestOption defaultOption = {0, DEAFULT_KEEP_LEN, 0};
    if (option == nullptr) {
        option = &defaultOption;
    }
    if (option->timeout > MAX_KEEP_LEN) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo input error, timeout too len.");
        return ERR_INVALID_PARA;
    }

    auto registry = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (registry == nullptr) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo get registry error.");
        return ERR_IPC_REGISTER_ERR;
    }
    auto object = registry->GetSystemAbility(DEVICE_SECURITY_LEVEL_MANAGER_SA_ID);
    if (object == nullptr) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo get object error.");
        return ERR_IPC_REMOTE_OBJ_ERR;
    }
    auto proxy = iface_cast<DeviceSecurityLevelProxy>(object);
    if (object == nullptr) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo iface_cast error.");
        return ERR_IPC_REMOTE_OBJ_ERR;
    }
    auto &helper = DelayedRefSingleton<DeviceSecurityLevelCallbackHelper>::GetInstance();
    sptr<DeviceSecurityLevelCallbackStub> stub = nullptr;
    uint32_t cookie = 0;

    auto result = helper.Publish(*identify, callback, option->timeout, stub, cookie);
    if (result == false || stub == nullptr || cookie == 0) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo get stub error.");
        return result;
    }

    auto success = proxy->RequestDeviceSecurityLevel(*identify, *option, stub->AsObject(), cookie);
    if (success != SUCCESS) {
        HiLog::Error(LABEL, "GetDeviceSecurityInfo RequestDeviceSecurityLevel error.");
        helper.withdraw(cookie);
    }

    return success;
}

static int32_t RequestDeviceSecurityInfoImpl(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfo **info)
{
    std::promise<DeviceSecurityInfo *> promise;

    auto callback = [&promise](const DeviceIdentify *identify, struct DeviceSecurityInfo *info) {
        promise.set_value(info);
        return;
    };
    auto result = RequestDeviceSecurityInfoAsyncImpl(identify, option, callback);
    if (result != SUCCESS) {
        HiLog::Error(LABEL, "RequestDeviceSecurityInfoImpl RequestDeviceSecurityLevel error.");
        return result;
    }
    *info = promise.get_future().get();
    return SUCCESS;
}

static void FreeDeviceSecurityInfoImpl(DeviceSecurityInfo *info)
{
    if (info != nullptr && info->magicNum == SECURITY_MAGIC) {
        info->magicNum = 0;
        delete info;
    }
}

static int32_t GetDeviceSecurityLevelValueImpl(const DeviceSecurityInfo *info, int32_t *level)
{
    if (info == nullptr || level == nullptr) {
        return ERR_INVALID_PARA;
    }
    if (info->magicNum != SECURITY_MAGIC) {
        return ERR_INVALID_PARA;
    }

    *level = info->level;
    return info->result;
}

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif
