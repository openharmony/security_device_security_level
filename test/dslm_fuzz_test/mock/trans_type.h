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

#ifndef SOCKET_TYPE_H
#define SOCKET_TYPE_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MAC_LEN  18
#define MAX_IP_LEN  46
#define MAX_PATH_LEN 4096
#define DEVICE_ID_LEN_MAX 65
#define ACCOUNT_UID_LEN_MAX 65
#define EXTRA_ACCESS_INFO_LEN_MAX 256

typedef enum {
    DATA_TYPE_BYTES,               /**< Bytes */
    DATA_TYPE_BUTT,
} TransDataType;

typedef struct {
    char *name;             /**< My socket name, maximum length 255 bytes */
    char *peerName;         /**< Peer socket name, maximum length 255 bytes */
    char *peerNetworkId;    /**< Peer network ID, maximum length 64 bytes */
    char *pkgName;          /**< Package name, maximum length 64 bytes */
    TransDataType dataType; /**< Data type */
} SocketInfo;

typedef struct {
    char *name;              /**< Peer socket name, maximum length 255 bytes */
    char *networkId;         /**< Peer network ID, maximum length 64 bytes */
    char *pkgName;           /**< Peer package name, maximum length 64 bytes */
    TransDataType dataType; /**< Data type of peer socket*/
} PeerSocketInfo;

typedef enum {
    SHUTDOWN_REASON_LOCAL,         /**< Shutdown by local process */
} ShutdownReason;

typedef enum {
    QOS_TYPE_MIN_BW,            /**< Minimum bandwidth. */
    QOS_TYPE_MAX_LATENCY = 1,       /**< Maximum latency. */
    QOS_TYPE_MIN_LATENCY,       /**< Minimum latency. */
    QOS_TYPE_MAX_IDLE_TIMEOUT,  /**< Maximum idle time. */
    QOS_TYPE_BUTT,
} QosType;

typedef struct {
    QosType qos;   /**< Qos type {@link QosType} */
    int32_t value; /**< Value of Qos types */
} QosTV;

#ifdef __cplusplus
}
#endif
#endif // SOCKET_TYPE_H