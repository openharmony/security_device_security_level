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

#ifndef DSLM_SERVICE_IPC_INTERFACE_CODE_H
#define DSLM_SERVICE_IPC_INTERFACE_CODE_H

#include <cstdint>

/* SAID: 3511 */
namespace OHOS {
namespace Security {
namespace DeviceSecurityLevel {
enum class DeviceSecurityLevelInterfaceCode {
    CMD_GET_DEVICE_SECURITY_LEVEL = 1,
};

enum class DeviceSecurityLevelCallbackInterfaceCode {
    CMD_SET_DEVICE_SECURITY_LEVEL = 1,
};
} // namespace DeviceSecurityLevel
} // namespace Security
} // namespace OHOS

#endif // DSLM_SERVICE_IPC_INTERFACE_CODE_H
