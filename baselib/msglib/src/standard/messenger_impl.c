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

#include "messenger_impl.h"

#include <stdlib.h>

#include "securec.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_work_queue.h"

#include "messenger.h"
#include "messenger_device_session_manager.h"
#include "messenger_device_status_manager.h"

#define MESSENGER_MAGIC_HEAD 0x1234abcd
#define MESSENGER_PROCESS_QUEUE_SIZE 256
#define MESSENGER_PROCESS_QUEUE_NAME "messenger_queue"
typedef struct Messenger {
    uint32_t magicHead;
    WorkQueue *processQueue;
} Messenger;

Messenger *CreateMessengerImpl(const MessengerConfig *cfg)
{
    if (cfg == NULL) {
        SECURITY_LOG_ERROR("CreateMessengerImpl error para");
        return NULL;
    }

    WorkQueue *processQueue = CreateWorkQueue(MESSENGER_PROCESS_QUEUE_SIZE, MESSENGER_PROCESS_QUEUE_NAME);
    if (processQueue == NULL) {
        return NULL;
    }

    bool result = InitDeviceSessionManager(processQueue, cfg->pkgName, cfg->sessName, cfg->messageReceiver,
        cfg->sendResultNotifier);
    if (result == false) {
        DestroyWorkQueue(processQueue);
        return NULL;
    }

    result = InitDeviceStatusManager(processQueue, cfg->pkgName, cfg->statusReceiver);
    if (result == false) {
        DestroyWorkQueue(processQueue);
        return NULL;
    }

    Messenger *messenger = MALLOC(sizeof(Messenger));
    if (messenger == NULL) {
        DestroyWorkQueue(processQueue);
        return NULL;
    }
    messenger->magicHead = MESSENGER_MAGIC_HEAD;
    messenger->processQueue = processQueue;

    return messenger;
}

void DestroyMessengerImpl(Messenger *messenger)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("DestroyMessengerImpl error para");
        return;
    }
    DeInitDeviceStatusManager();
    DeInitDeviceSessionManager();
    messenger->magicHead = 0;
    DestroyWorkQueue(messenger->processQueue);
    FREE(messenger);
    return;
}

bool IsMessengerReadyImpl(const Messenger *messenger)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("IsMessengerReadyImpl error para");
        return false;
    }
    return true;
}

void SendMsgToImpl(const Messenger *messenger, uint64_t transNo, const DeviceIdentify *devId, const uint8_t *msg,
    uint32_t msgLen)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("SendMsgToImpl error para");
        return;
    }
    MessengerSendMsgTo(transNo, devId, msg, msgLen);
}

bool GetDeviceOnlineStatusImpl(const Messenger *messenger, const DeviceIdentify *devId, uint32_t *devType)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("GetDeviceOnlineStatusImpl error para");
        return false;
    }

    return MessengerGetDeviceOnlineStatus(devId, devType);
}

bool GetSelfDeviceIdentifyImpl(const Messenger *messenger, DeviceIdentify *devId, uint32_t *devType)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("GetSelfDeviceIdentifyImpl error para");
        return false;
    }

    return MessengerGetSelfDeviceIdentify(devId, devType);
}

void ForEachDeviceProcessImpl(const Messenger *messenger, const DeviceProcessor processor, void *para)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("ForEachDeviceProcessImpl error para");
        return;
    }

    return MessengerForEachDeviceProcess(processor, para);
}

bool GetDeviceStatisticInfoImpl(const Messenger *messenger, const DeviceIdentify *devId, StatisticInformation *info)
{
    if (messenger == NULL || messenger->magicHead != MESSENGER_MAGIC_HEAD) {
        SECURITY_LOG_ERROR("GetDeviceStatisticInfoImpl error para");
        return false;
    }
    return true;
}
