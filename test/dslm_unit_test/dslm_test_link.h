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

#ifndef DSLM_UNIT_TEST_LINK_LIB_TEST_H
#define DSLM_UNIT_TEST_LINK_LIB_TEST_H

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#include "messenger_device_socket_manager.h"
#include "socket.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct DeviceSocketManager DeviceSocketManager;
typedef struct SocketNodeInfo SocketNodeInfo;

DeviceSocketManager *UtGetDeviceSocketManagerInstance(void);

void UtProcessSocketMessageReceived(const uint8_t *data, uint32_t len);

void UtRemoveSocketNode(int32_t socket, ShutdownReason reason, bool isServer);

void UtOnSocketMessageReceived(const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen);

bool UtGetIdentityBySocketId(int32_t socket, bool isServer, DeviceIdentify *identity);

void UtServerOnBind(int32_t socket, PeerSocketInfo info);

void UtClientOnBind(int socket, const DeviceIdentify *devId);

void UtServerOnShutdown(int32_t socket, ShutdownReason reason);

void UtClientOnShutdown(int32_t socket, ShutdownReason reason);

void UtTimerProcessWaitingTimeOut(const void *context);

void UtCreateOrRestartSocketCloseTimerWithLock(int32_t socket);

bool UtGetIdentityByServerSocket(int32_t socket, DeviceIdentify *identity);

bool UtGetIdentityByClientSocket(int32_t socket, DeviceIdentify *identity);

SocketNodeInfo *UtCreateSocketNodeInfo(int32_t socket, const DeviceIdentify *identity);

void UtServerOnBytes(int32_t socket, const void *data, unsigned int dataLen);

void UtClientOnBytes(int32_t socket, const void *data, unsigned int dataLen);

bool UtCreateServer(DeviceSocketManager *inst);

bool UtBindSync(int32_t socket, const DeviceIdentify *devId);

int32_t UtGetClientName(char *clientName, const char *name, uint32_t maskId, bool isSame);

bool UtGetSocketBySocketList(const DeviceIdentify *devId, bool isServer, int32_t *socket);

void UtPushMsgDataToPendingList(uint32_t transNo, const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen);

#ifdef __cplusplus
}
#endif

#endif // DSLM_UNIT_TEST_LINK_LIB_TEST_H