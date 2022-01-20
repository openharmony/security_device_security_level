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

#include <stdlib.h>

#include "securec.h"
#include "session.h"
#include "softbus_bus_center.h"

#include "utils_list.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_mutex.h"

#include "messenger_device_session_manager.h"
#include "messenger_device_status_manager.h"
#include "messenger_utils.h"

#define IS_SERVER 0

static int MessengerOnSessionOpened(int sessionId, int result);
static void MessengerOnSessionClosed(int sessionId);
static void MessengerOnBytesReceived(int sessionId, const void *data, unsigned int dataLen);
static void MessengerOnMessageReceived(int sessionId, const void *data, unsigned int dataLen);

typedef struct DeviceSessionManager {
    const ISessionListener listener;
    ListHead pendingSendList;
    ListHead opendSessionList;
    DeviceMessageReceiver messageReceiver;
    MessageSendResultNotifier sendResultNotifier;
    const char *pkgName;
    const char *sessionName;
    WorkQueue *queue;
    Mutex mutex;
} DeviceSessionManager;

typedef struct QueueMsgData {
    DeviceIdentify srcIdentity;
    uint32_t msgLen;
    uint8_t msgdata[1];
} QueueMsgData;

typedef struct PendingMsgData {
    ListNode link;
    uint32_t transNo;
    DeviceIdentify destIdentity;
    uint32_t msgLen;
    uint8_t msgdata[1];
} PendingMsgData;

typedef struct SessionInfo {
    ListNode link;
    int32_t sessionId;
    uint32_t maskId;
    DeviceIdentify identity;
} SessionInfo;

static inline DeviceSessionManager *GetDeviceSessionManagerInstance(void)
{
    static DeviceSessionManager manager = {
        {
            .OnSessionOpened = MessengerOnSessionOpened,
            .OnSessionClosed = MessengerOnSessionClosed,
            .OnBytesReceived = MessengerOnBytesReceived,
            .OnMessageReceived = MessengerOnMessageReceived,
        },
        .pendingSendList = INIT_LIST(manager.pendingSendList),
        .opendSessionList = INIT_LIST(manager.opendSessionList),
        .messageReceiver = NULL,
        .sendResultNotifier = NULL,
        .queue = NULL,
        .mutex = INITED_MUTEX,
    };
    return &manager;
}

static void ProcessSessionMessageReceived(const uint8_t *data, uint32_t len)
{
    if (data == NULL || len == 0) {
        return;
    }
    QueueMsgData *queueData = (QueueMsgData *)data;
    if (queueData->msgLen + sizeof(QueueMsgData) != len) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, invalid input");
        return;
    }

    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    DeviceMessageReceiver messageReceiver = instance->messageReceiver;
    if (messageReceiver == NULL) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, messageReceiver is null");
        return;
    }
    messageReceiver(&queueData->srcIdentity, queueData->msgdata, queueData->msgLen);
    FREE(queueData);
}

static inline void OnSessionMessageReceived(const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen)
{
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    WorkQueue *queue = instance->queue;
    if (queue == NULL) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, queue is null");
        return;
    }
    DeviceMessageReceiver messageReceiver = instance->messageReceiver;
    if (messageReceiver == NULL) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, messageReceiver is null");
        return;
    }
    uint32_t queueDataLen = sizeof(QueueMsgData) + msgLen;
    QueueMsgData *queueData = MALLOC(queueDataLen);
    if (queueData == NULL) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, malloc result null");
        return;
    }
    uint32_t ret = memcpy_s(&queueData->srcIdentity, sizeof(DeviceIdentify), devId, sizeof(DeviceIdentify));
    if (ret != EOK) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, memcpy failed");
        FREE(queueData);
        return;
    }
    ret = memcpy_s(queueData->msgdata, msgLen, msg, msgLen);
    if (ret != EOK) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, memcpy failed");
        FREE(queueData);
        return;
    }
    queueData->msgLen = msgLen;
    ret = QueueWork(queue, ProcessSessionMessageReceived, (uint8_t *)queueData, queueDataLen);
    if (ret != WORK_QUEUE_OK) {
        SECURITY_LOG_ERROR("ProcessSessionMessageReceived, QueueWork failed, ret is %{public}u", ret);
        FREE(queueData);
        return;
    }
}

static bool GetDeviceIdentityFromSessionId(int sessionId, DeviceIdentify *identity, uint32_t *maskId)
{
    if (identity == NULL || maskId == NULL) {
        return false;
    }
    char deviceName[DEVICE_ID_MAX_LEN + 1] = {0};
    int ret = GetPeerDeviceId(sessionId, deviceName, DEVICE_ID_MAX_LEN + 1);
    if (ret != 0) {
        SECURITY_LOG_INFO("GetDeviceIdentityFromSessionId %{public}d failed, result is %{public}d", sessionId, ret);
        return false;
    }

    char udid[UDID_BUF_LEN] = {0};
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    if (GetNodeKeyInfo(instance->pkgName, deviceName, NODE_KEY_UDID, (uint8_t *)udid, UDID_BUF_LEN) != 0) {
        SECURITY_LOG_ERROR("MessengerGetSelfDeviceIdentify GetNodeKeyInfo error.");
        return false;
    }

    *maskId = MaskDeviceIdentity(udid, DEVICE_ID_MAX_LEN);
    identity->length = DEVICE_ID_MAX_LEN;
    memcpy_s(&identity->identity, DEVICE_ID_MAX_LEN, udid, DEVICE_ID_MAX_LEN);
    return true;
}

static int MessengerOnSessionOpened(int sessionId, int result)
{
    int side = GetSessionSide(sessionId);
    SECURITY_LOG_INFO("MessengerOnSessionOpened id=%{public}d, side=%{public}s, result=%{public}d", sessionId,
        (side == IS_SERVER) ? "server" : "client", result);

    if (side == IS_SERVER) {
        return 0;
    }
    if (result != 0) {
        return 0;
    }

    DeviceIdentify identity = {DEVICE_ID_MAX_LEN, {0}};
    uint32_t maskId;
    bool ret = GetDeviceIdentityFromSessionId(sessionId, &identity, &maskId);
    if (ret == false) {
        SECURITY_LOG_ERROR("MessengerOnSessionOpened GetDeviceIdentityFromSessionId failed");
        return 0;
    }

    SessionInfo *sessionInfo = MALLOC(sizeof(SessionInfo));
    if (sessionInfo == NULL) {
        SECURITY_LOG_ERROR("MessengerOnSessionOpened malloc failed");
        return 0;
    }
    sessionInfo->sessionId = sessionId;
    sessionInfo->maskId = maskId;
    memcpy_s(&sessionInfo->identity, sizeof(DeviceIdentify), &identity, sizeof(DeviceIdentify));

    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    LockMutex(&instance->mutex);
    AddListNodeBefore(&sessionInfo->link, &instance->opendSessionList);

    ListNode *node = NULL;
    ListNode *temp = NULL;

    FOREACH_LIST_NODE_SAFE (node, &instance->pendingSendList, temp) {
        PendingMsgData *MsgData = LIST_ENTRY(node, PendingMsgData, link);
        if (!IsSameDevice(&MsgData->destIdentity, &identity)) {
            continue;
        }

        RemoveListNode(node);
        int ret = SendBytes(sessionId, MsgData->msgdata, MsgData->msgLen);
        if (ret != 0) {
            SECURITY_LOG_ERROR("MessengerSendMsgTo SendBytes error code = %{publc}d", ret);
        }
        FREE(MsgData);
    }

    UnlockMutex(&instance->mutex);
    return 0;
}

static void MessengerOnSessionClosed(int sessionId)
{
    int side = GetSessionSide(sessionId);
    SECURITY_LOG_INFO("MessengerOnSessionClosed id=%{public}d, side=%{public}s", sessionId,
        (side == IS_SERVER) ? "server" : "client");

    if (side == IS_SERVER) {
        return;
    }

    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    LockMutex(&instance->mutex);
    ListNode *node = NULL;
    ListNode *temp = NULL;
    FOREACH_LIST_NODE_SAFE (node, &instance->opendSessionList, temp) {
        SessionInfo *info = LIST_ENTRY(node, SessionInfo, link);
        if (info->sessionId == sessionId) {
            SECURITY_LOG_INFO("MessengerOnSessionClosed device=%{public}x", info->maskId);
            RemoveListNode(node);
            FREE(info);
        }
    }
    UnlockMutex(&instance->mutex);
    return;
}

static void MessengerOnBytesReceived(int sessionId, const void *data, unsigned int dataLen)
{
    DeviceIdentify identity = {DEVICE_ID_MAX_LEN, {0}};
    uint32_t maskId;
    bool ret = GetDeviceIdentityFromSessionId(sessionId, &identity, &maskId);
    if (ret == false) {
        return;
    }
    SECURITY_LOG_INFO("MessengerOnBytesReceived from device(%{public}x***, data length is %{public}u", maskId, dataLen);
    OnSessionMessageReceived(&identity, (const uint8_t *)data, (uint32_t)dataLen);
}

static void MessengerOnMessageReceived(int sessionId, const void *data, unsigned int dataLen)
{
    return MessengerOnBytesReceived(sessionId, data, dataLen);
}

bool InitDeviceSessionManager(WorkQueue *queue, const char *pkgName, const char *sessionName,
    DeviceMessageReceiver messageReceiver, MessageSendResultNotifier sendResultNotifier)
{
    if ((pkgName == NULL) || (sessionName == NULL)) {
        return false;
    }
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    instance->pkgName = pkgName;
    instance->sessionName = sessionName;
    instance->messageReceiver = messageReceiver;
    instance->sendResultNotifier = sendResultNotifier;
    instance->queue = queue;
    int try = 0;
    int ret = CreateSessionServer(pkgName, sessionName, &instance->listener);
    while (ret != 0 && try < MAX_TRY_TIMES) {
        MessengerSleep(1); // sleep 1 second and try again
        ret = CreateSessionServer(pkgName, sessionName, &instance->listener);
        try++;
    }

    if (ret != 0) {
        SECURITY_LOG_ERROR("InitSessionManager CreateSessionServer failed = %{public}d", ret);
        return false;
    }

    SECURITY_LOG_INFO("InitSessionManager CreateSessionServer success");
    return true;
}

bool DeInitDeviceSessionManager()
{
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    int ret = RemoveSessionServer(instance->pkgName, instance->sessionName);
    if (ret != 0) {
        SECURITY_LOG_ERROR("DeInitSessionManager RemoveSessionServer failed = %{public}d", ret);
        return false;
    }
    LockMutex(&instance->mutex);
    instance->pkgName = NULL;
    instance->sessionName = NULL;
    instance->messageReceiver = NULL;
    instance->sendResultNotifier = NULL;
    instance->queue = NULL;

    ListNode *node = NULL;
    ListNode *temp = NULL;

    FOREACH_LIST_NODE_SAFE (node, &instance->pendingSendList, temp) {
        PendingMsgData *MsgData = LIST_ENTRY(node, PendingMsgData, link);
        RemoveListNode(node);
        FREE(MsgData);
    }

    FOREACH_LIST_NODE_SAFE (node, &instance->opendSessionList, temp) {
        SessionInfo *info = LIST_ENTRY(node, SessionInfo, link);
        RemoveListNode(node);
        FREE(info);
    }

    DestroyWorkQueue(instance->queue);
    UnlockMutex(&instance->mutex);

    SECURITY_LOG_INFO("DeInitSessionManager RemoveSessionServer success");
    return true;
}

static bool GetOpenedSessionId(const DeviceIdentify *devId, int32_t *sessionId)
{
    if (devId == NULL || sessionId == NULL) {
        return false;
    }
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();

    bool find = false;
    LockMutex(&instance->mutex);
    ListNode *node = NULL;
    uint32_t mask = MaskDeviceIdentity((const char *)&devId->identity[0], devId->length);

    FOREACH_LIST_NODE (node, &instance->opendSessionList) {
        SessionInfo *sessionInfo = LIST_ENTRY(node, SessionInfo, link);
        if (IsSameDevice(&sessionInfo->identity, devId)) {
            *sessionId = sessionInfo->sessionId;
            find = true;
            break;
        }
    }
    UnlockMutex(&instance->mutex);
    SECURITY_LOG_DEBUG("GetOpenedSessionId for device %{public}x %{public}s", mask, find ? "exist" : "no exist");
    return find;
}

static void PushMsgDataToPendingList(uint32_t transNo, const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen)
{
    PendingMsgData *data = MALLOC(sizeof(PendingMsgData) + msgLen);
    if (data == NULL) {
        SECURITY_LOG_ERROR("PushMsgDataToPendingList malloc error");
        return;
    }
    data->transNo = transNo;
    data->msgLen = msgLen;
    memcpy_s(&data->destIdentity, sizeof(DeviceIdentify), devId, sizeof(DeviceIdentify));
    memcpy_s(data->msgdata, msgLen, msg, msgLen);
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    LockMutex(&instance->mutex);
    AddListNodeBefore(&data->link, &instance->pendingSendList);
    UnlockMutex(&instance->mutex);
}

static void CreateNewDeviceSession(const DeviceIdentify *devId)
{
    uint32_t mask = MaskDeviceIdentity((const char *)&devId->identity[0], devId->length);
    char deviceName[DEVICE_ID_MAX_LEN + 1] = {0};
    bool succ = MessengerGetDeviceNetworkId(devId, deviceName, DEVICE_ID_MAX_LEN + 1);
    if (!succ) {
        SECURITY_LOG_ERROR("CreateNewDeviceSession get network id error");
        return;
    }

    const SessionAttribute attr = {
        .dataType = TYPE_MESSAGE,
    };
    DeviceSessionManager *instance = GetDeviceSessionManagerInstance();
    int ret = OpenSession(instance->sessionName, instance->sessionName, deviceName, "", &attr);
    if (ret <= 0) {
        // open failed, need to try again.
        ret = OpenSession(instance->sessionName, instance->sessionName, deviceName, "", &attr);
    }
    SECURITY_LOG_INFO("CreateNewDeviceSession for device %{public}x ret is %{public}d", mask, ret);
}

void MessengerSendMsgTo(uint64_t transNo, const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen)
{
    if (devId == NULL || msg == NULL || msgLen == 0) {
        SECURITY_LOG_ERROR("MessengerSendMsgTo error for invalid para");
        return;
    }

    static DeviceIdentify self = {0, {0}};
    uint32_t devType;
    MessengerGetSelfDeviceIdentify(&self, &devType);

    if (IsSameDevice(&self, devId)) {
        SECURITY_LOG_DEBUG("MessengerSendMsgTo loopback msg");
        OnSessionMessageReceived(devId, msg, msgLen);
        return;
    }

    int32_t sessionId;
    bool find = GetOpenedSessionId(devId, &sessionId);
    if (find) {
        int ret = SendBytes(sessionId, msg, msgLen);
        if (ret != 0) {
            SECURITY_LOG_ERROR("MessengerSendMsgTo SendBytes error code = %{publc}d", ret);
        }
    } else {
        PushMsgDataToPendingList(transNo, devId, msg, msgLen);
        CreateNewDeviceSession(devId);
    }
}