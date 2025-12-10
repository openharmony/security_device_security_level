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

#include "device_security_level_callback_stub.h"

#include <functional>
#include <string>
#include <type_traits>

#include "hilog/log_cpp.h"

#include "device_security_defines.h"
#include "device_security_level_defines.h"

namespace OHOS {
namespace Security {
namespace DeviceSecurityLevel {
using namespace OHOS::HiviewDFX;
DeviceSecurityLevelCallbackStub::DeviceSecurityLevelCallbackStub(RemoteRequest request, RemoteResponse response)
    : remoteRequest_(std::move(request)), remoteResponse_(std::move(response))
{
}

int32_t DeviceSecurityLevelCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    if (DeviceSecurityLevelCallbackStub::GetDescriptor() != data.ReadInterfaceToken()) {
        HILOG_ERROR(LOG_CORE, "descriptor not match");
        return SUCCESS;
    }

    uint32_t cookie;
    uint32_t result;
    uint32_t level;

    if (remoteRequest_ == nullptr) {
        return SUCCESS;
    }
    int32_t ret = remoteRequest_(code, data, cookie, result, level);
    if (ret != SUCCESS) {
        return ret;
    }

    ResponseInfo info = {
        .result = result,
        .level = level,
    };
    return ResponseDeviceSecurityLevel(cookie, info);
}

int32_t DeviceSecurityLevelCallbackStub::ResponseDeviceSecurityLevel(uint32_t cookie, const ResponseInfo &response)
{
    if (remoteResponse_ != nullptr) {
        return remoteResponse_(cookie, response.result, response.level);
    }

    return SUCCESS;
}
} // namespace DeviceSecurityLevel
} // namespace Security
} // namespace OHOS
