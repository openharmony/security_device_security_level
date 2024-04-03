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

#ifndef SEC_MESSENGER_IMPL_H
#define SEC_MESSENGER_IMPL_H

#include "messenger.h"

#ifdef __cplusplus
extern "C" {
#endif

Messenger *CreateMessengerImpl(const MessengerConfig *config);

void DestroyMessengerImpl(Messenger *messenger);

void SendMsgToImpl(const Messenger *messenger, uint64_t transNo, const DeviceIdentify *devId, const uint8_t *msg,
    uint32_t msgLen);

bool IsMessengerReadyImpl(const Messenger *messenger);

bool GetDeviceOnlineStatusImpl(const Messenger *messenger, const DeviceIdentify *devId, int32_t *level);

bool GetSelfDeviceIdentifyImpl(const Messenger *messenger, DeviceIdentify *devId, int32_t *level);

void ForEachDeviceProcessImpl(const Messenger *messenger, const DeviceProcessor processor, void *para);

bool GetDeviceStatisticInfoImpl(const Messenger *messenger, const DeviceIdentify *devId, StatisticInformation *info);

#ifdef __cplusplus
}
#endif

#endif // SEC_MESSENGER_IMPL_H
