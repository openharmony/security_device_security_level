/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DM_MANAGER_MOCK_H
#define OHOS_DM_MANAGER_MOCK_H

#include <cstdint>
#include <string>

#include <gmock/gmock.h>

#include "device_manager.h"
#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
class DeviceManagerMock : public DeviceManager {
public:
    static DeviceManagerMock &Instance();
    DeviceManagerMock();
    ~DeviceManagerMock();
    MOCK_METHOD(int32_t, InitDeviceManager,
        (const std::string &pkgName, std::shared_ptr<DmInitCallback> dmInitCallback), (override));

    MOCK_METHOD(int32_t, UnInitDeviceManager, (const std::string &pkgName), (override));

    MOCK_METHOD(int32_t, GetTrustedDeviceList,
        (const std::string &pkgName, const std::string &extra, std::vector<DmDeviceInfo> &deviceList), (override));

    MOCK_METHOD(int32_t, GetLocalDeviceInfo, (const std::string &pkgName, DmDeviceInfo &deviceInfo), (override));

    MOCK_METHOD(int32_t, GetUdidByNetworkId,
        (const std::string &pkgName, const std::string &netWorkId, std::string &udid), (override));

    MOCK_METHOD(int32_t, GetDeviceSecurityLevel,
        (const std::string &pkgName, const std::string &networkId, int32_t &securityLevel), (override));
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DM_MANAGER_MOCK_H
