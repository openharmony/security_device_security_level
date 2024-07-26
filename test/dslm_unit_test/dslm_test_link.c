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
#include "dslm_test_link.h"

#include "socket.h"

DeviceSocketManager *UtGetDeviceSocketManagerInstance(void)
{
    return GetDeviceSocketManagerInstance();
}

void UtProcessSocketMessageReceived(const uint8_t *data, uint32_t len)
{
    ProcessSocketMessageReceived(data, len);
}

void UtRemoveSocketNode(int32_t socket, ShutdownReason reason, bool isServer)
{
    RemoveSocketNode(socket, reason, isServer);
}

void UtOnSocketMessageReceived(const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen)
{
    OnSocketMessageReceived(devId, msg, msgLen);
}

bool UtGetIdentityBySocketId(int32_t socket, bool isServer, DeviceIdentify *identity)
{
    return GetIdentityBySocketId(socket, isServer, identity);
}

void UtServerOnBind(int32_t socket, PeerSocketInfo info)
{
    ServerOnBind(socket, info);
}

void UtClientOnBind(int socket, const DeviceIdentify *devId)
{
    ClientOnBind(socket, devId);
}

void UtServerOnShutdown(int32_t socket, ShutdownReason reason)
{
    ServerOnShutdown(socket, reason);
}

void UtClientOnShutdown(int32_t socket, ShutdownReason reason)
{
    ClientOnShutdown(socket, reason);
}

void UtTimerProcessWaitingTimeOut(const void *context)
{
    TimerProcessWaitingTimeOut(context);
}

void UtCreateOrRestartSocketCloseTimerWithLock(int32_t socket)
{
    CreateOrRestartSocketCloseTimerWithLock(socket);
}

bool UtGetIdentityByServerSocket(int32_t socket, DeviceIdentify *identity)
{
    return GetIdentityByServerSocket(socket, identity);
}

bool UtGetIdentityByClientSocket(int32_t socket, DeviceIdentify *identity)
{
    return GetIdentityByClientSocket(socket, identity);
}

SocketNodeInfo *UtCreateSocketNodeInfo(int32_t socket, const DeviceIdentify *identity)
{
    return CreateSocketNodeInfo(socket, identity);
}

void UtServerOnBytes(int32_t socket, const void *data, unsigned int dataLen)
{
    ServerOnBytes(socket, data, dataLen);
}

void UtClientOnBytes(int32_t socket, const void *data, unsigned int dataLen)
{
    ClientOnBytes(socket, data, dataLen);
}

bool UtCreateServer(DeviceSocketManager *inst)
{
    return CreateServer(inst);
}

bool UtBindSync(int32_t socket, const DeviceIdentify *devId)
{
    return BindSync(socket, devId);
}

int32_t UtGetClientName(char *clientName, const char *name, uint32_t maskId, bool isSame)
{
    return GetClientName(clientName, name, maskId, isSame);
}

bool UtGetSocketBySocketList(const DeviceIdentify *devId, bool isServer, int32_t *socket)
{
    return GetSocketBySocketList(devId, isServer, socket);
}

void UtPushMsgDataToPendingList(uint32_t transNo, const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen)
{
    PushMsgDataToPendingList(transNo, devId, msg, msgLen);
}