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

#ifndef DSLM_MSG_INTERFACE_MOCK_H
#define DSLM_MSG_INTERFACE_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "socket.h"

#include "dslm_callback_info.h"
#include "messenger.h"

namespace OHOS {
namespace Security {
namespace DslmUnitTest {
class DslmMsgInterface {
public:
    DslmMsgInterface() {};
    virtual ~DslmMsgInterface() {};

    virtual bool IsMessengerReady(const Messenger *messenger) = 0;

    virtual uint64_t SendMsgTo(const Messenger *messenger, uint64_t transNo, const DeviceIdentify *devId,
        const uint8_t *msg, uint32_t msgLen) = 0;

    virtual bool GetDeviceOnlineStatus(const Messenger *messenger, const DeviceIdentify *devId, int32_t *level) = 0;

    virtual bool GetSelfDeviceIdentify(const Messenger *messenger, DeviceIdentify *devId, int32_t *level) = 0;

    virtual void ForEachDeviceProcess(const Messenger *messenger, const DeviceProcessor processor, void *para) = 0;

    virtual int32_t Socket(SocketInfo info) = 0;

    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;

    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener) = 0;

    virtual int32_t SendBytes(int32_t socket, const void *data, uint32_t len) = 0;

    virtual void Shutdown(int32_t socket) = 0;
};

class DslmMsgInterfaceMock : public DslmMsgInterface {
public:
    DslmMsgInterfaceMock();
    ~DslmMsgInterfaceMock() override;
    MOCK_METHOD(bool, IsMessengerReady, (const Messenger *messenger), (override));
    MOCK_METHOD(uint64_t, SendMsgTo, (const Messenger *messenger, uint64_t transNo, const DeviceIdentify *devId,
                                const uint8_t *msg, uint32_t msgLen), (override));
    MOCK_METHOD(bool, GetDeviceOnlineStatus,
        (const Messenger *messenger, const DeviceIdentify *devId, int32_t *level), (override));
    MOCK_METHOD(bool, GetSelfDeviceIdentify, (const Messenger *messenger, DeviceIdentify *devId, int32_t *level),
        (override));
    MOCK_METHOD(void, ForEachDeviceProcess, (const Messenger *messenger, const DeviceProcessor processor, void *para),
        (override));
    MOCK_METHOD(int32_t, Socket, (SocketInfo info), (override));
    MOCK_METHOD(int32_t, Listen,
        (int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener *listener), (override));
    MOCK_METHOD(int32_t, Bind, (int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener *listener), (override));
    MOCK_METHOD(int32_t, SendBytes, (int32_t socket, const void *data, uint32_t len), (override));
    MOCK_METHOD(void, Shutdown, (int32_t socket), (override));
    void MakeMsgLoopback() const;
    void MakeSelfDeviceId(const DeviceIdentify *devId) const;
    void MakeDeviceOnline(const DeviceIdentify *devId) const;
    void MakeDeviceOffline(const DeviceIdentify *devId) const;
    void MakeMsgReceivedFrom(const DeviceIdentify *devId, const uint8_t *msg, uint32_t msgLen) const;
};
} // namespace DslmUnitTest
} // namespace Security
} // namespace OHOS

#endif // DSLM_MSG_INTERFACE_MOCK_H
