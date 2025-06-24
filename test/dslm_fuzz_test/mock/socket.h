/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SOCKET_H
#define SOCKET_H

#include <stdint.h>
#include <stdbool.h>
#include "trans_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QOS_SATISFIED,     /**< Feedback on satisfied quality */
    QOS_NOT_SATISFIED, /**< Feedback on not satisfied quality */
} QoSEvent;

typedef struct {
    void (*OnBind)(int32_t socket, PeerSocketInfo info);

    void (*OnShutdown)(int32_t socket, ShutdownReason reason);

    void (*OnBytes)(int32_t socket, const void *data, uint32_t dataLen);

    void (*OnMessage)(int32_t socket, const void *data, uint32_t dataLen);
} ISocketListener;

int32_t Socket(SocketInfo info);

int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener);

int32_t SendBytes(int32_t socket, const void *data, uint32_t len);

void Shutdown(int32_t socket);

#ifdef __cplusplus
}
#endif
#endif // SOCKET_H
