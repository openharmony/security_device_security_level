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

#ifndef SEC_MESSENGER_DEVICE_STATUS_MANAGER_H
#define SEC_MESSENGER_DEVICE_STATUS_MANAGER_H

#include "messenger.h"

#include "utils_work_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

bool InitDeviceStatusManager(WorkQueue *queue, const char *pkgName, DeviceStatusReceiver deviceStatusReceiver);

bool DeInitDeviceStatusManager();

bool MessengerGetDeviceOnlineStatus(const DeviceIdentify *devId, uint32_t *devType);

bool MessengerGetDeviceNetworkId(const DeviceIdentify *devId, char *networkId, uint32_t len);

bool MessengerGetSelfDeviceIdentify(DeviceIdentify *devId, uint32_t *devType);

void MessengerForEachDeviceProcess(const DeviceProcessor processor, void *para);

#ifdef __cplusplus
}
#endif

#endif // SEC_MESSENGER_DEVICE_STATUS_MANAGER_H
