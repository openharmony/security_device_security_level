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

#ifndef DSLM_CALLBACK_PROXY
#define DSLM_CALLBACK_PROXY

#include "iremote_proxy.h"
#include "nocopyable.h"

#include "idevice_security_level.h"

namespace OHOS {
namespace Security {
namespace DeviceSecurityLevel {
using namespace OHOS;
class DslmCallbackProxy : public IRemoteProxy<IDeviceSecurityLevelCallback> {
public:
    DISALLOW_COPY_AND_MOVE(DslmCallbackProxy);
    explicit DslmCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~DslmCallbackProxy() = default;

    struct ResponseInfo {
        uint32_t result;
        uint32_t level;
        const uint8_t *extraBuff;
        uint32_t extraLen;
    };

    int32_t ResponseDeviceSecurityLevel(uint32_t cookie, const ResponseInfo &response);

private:
    static inline BrokerDelegator<DslmCallbackProxy> delegator_;
};

} // namespace DeviceSecurityLevel
} // namespace Security
} // namespace OHOS

#endif // DSLM_CALLBACK_PROXY