/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <stdlib.h>

#include "securec.h"

#include "messenger_utils.h"
#include "utils_log.h"
#include "utils_mem.h"

QueueMsgData *CreateQueueMsgData(const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen,
    uint32_t *queueDataLen)
{
    if (devId == NULL || msg == NULL || msgLen == 0 || queueDataLen == NULL) {
        return NULL;
    }

    uint32_t dataLen = sizeof(QueueMsgData) + msgLen;
    QueueMsgData *queueData = MALLOC(dataLen);
    if (queueData == NULL) {
        SECURITY_LOG_ERROR("malloc result null");
        return NULL;
    }
    uint32_t ret = (uint32_t)memcpy_s(&queueData->srcIdentity, sizeof(DeviceIdentify), devId, sizeof(DeviceIdentify));
    if (ret != EOK) {
        SECURITY_LOG_ERROR("memcpy failed");
        FREE(queueData);
        return NULL;
    }
    ret = (uint32_t)memcpy_s(queueData->msgData, msgLen, msg, msgLen);
    if (ret != EOK) {
        SECURITY_LOG_ERROR("memcpy failed");
        FREE(queueData);
        return NULL;
    }
    queueData->msgLen = msgLen;
    *queueDataLen = dataLen;

    return queueData;
}
