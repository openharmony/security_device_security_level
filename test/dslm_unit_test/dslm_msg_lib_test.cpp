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

#include "dslm_msg_lib_test.h"

#include <cstdint>

#include "messenger.h"
#include "messenger_utils.h"
#include "securec.h"
#include "utils_log.h"
#include "utils_mem.h"

#include "device_manager_mock.h"
#include "dslm_msg_interface_mock.h"
#include "dslm_test_link.h"

#include "messenger_device_socket_manager.h"
#include "messenger_device_status_manager.h"

#define QUEUE_LEN 2

using namespace std;
using namespace std::chrono;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace DslmUnitTest {

std::string g_errLog;

void LogCallback(const LogType, const LogLevel level, const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

void DslmMsgLibTest::SetUpTestCase()
{
}
void DslmMsgLibTest::TearDownTestCase()
{
}
void DslmMsgLibTest::SetUp()
{
    queue = CreateWorkQueue(QUEUE_LEN, "msg_ut_test_queue");
}
void DslmMsgLibTest::TearDown()
{
    DestroyWorkQueue(queue);
    auto &mock = DistributedHardware::DeviceManagerMock::Instance();
    Mock::VerifyAndClearExpectations(&mock);
}

HWTEST_F(DslmMsgLibTest, MessengerCommonTest, TestSize.Level0)
{
    {
        auto *msg = CreateMessenger(nullptr);
        EXPECT_EQ(msg, nullptr);
    }
    {
        MessengerConfig config = {};
        auto *msg = CreateMessenger(&config);
        EXPECT_EQ(msg, nullptr);
        DestroyMessenger(msg);
    }
    {
        ForEachDeviceProcess(nullptr, nullptr, nullptr);
        EXPECT_FALSE(GetDeviceStatisticInfo(nullptr, nullptr, nullptr));
    }
}

HWTEST_F(DslmMsgLibTest, DeviceSocketTestCase1, TestSize.Level0)
{
    {
        auto result = InitDeviceSocketManager(nullptr, nullptr);
        EXPECT_EQ(result, false);
    }
    {
        auto result = InitDeviceSocketManager(queue, nullptr);
        EXPECT_EQ(result, false);
    }
    {
        MessengerConfig config = {};
        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_FALSE(ret);
        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
    {
        MessengerConfig config = {.pkgName = "pkg", .primarySockName = "", .secondarySockName = "se", .threadCnt = 1};
        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
    {
        MessengerConfig config = {.pkgName = "pkg", .primarySockName = "pr", .secondarySockName = "", .threadCnt = 1};
        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_TRUE(ret);
        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
}

HWTEST_F(DslmMsgLibTest, DeviceSocketTestCase2, TestSize.Level0)
{
    MessengerConfig config = {.pkgName = "pkg", .primarySockName = "pr", .secondarySockName = "se", .threadCnt = 1};
    auto ret = InitDeviceSocketManager(queue, &config);
    EXPECT_TRUE(ret);
    char dummy[] = {'a', 0};
    PeerSocketInfo peer = {.name = dummy, .networkId = dummy};
    {
        DeviceIdentify id {.identity = {'a'}, .length = 1};
        uint8_t msg[UINT8_MAX] = {0};
        UtPushMsgDataToPendingList(0, &id, msg, 1);
    }
    UtServerOnBind(1, peer);
    {
        DeviceIdentify idt {};
        EXPECT_FALSE(UtGetIdentityByServerSocket(1, nullptr));
        EXPECT_TRUE(UtGetIdentityByServerSocket(1, &idt));
        UtServerOnBytes(1, nullptr, 0);
        UtServerOnBytes(1, dummy, 1);
        UtServerOnBytes(0, dummy, 1);
        int sock = 0;
        EXPECT_TRUE(UtGetSocketBySocketList(&idt, true, &sock));
        EXPECT_EQ(sock, 1);
    }
    UtClientOnBind(2, nullptr);
    DeviceIdentify idt {.length = 1};
    UtClientOnBind(2, &idt);
    {
        DeviceIdentify idt {};
        EXPECT_FALSE(UtGetIdentityByClientSocket(2, nullptr));
        EXPECT_TRUE(UtGetIdentityByClientSocket(2, &idt));
        int sock = 0;
        EXPECT_TRUE(UtGetSocketBySocketList(&idt, false, &sock));
        EXPECT_EQ(sock, 2);
        UtClientOnBytes(2, nullptr, 0);
        UtClientOnBytes(2, dummy, 1);
        UtClientOnBytes(0, dummy, 1);
    }
    EXPECT_TRUE(DeInitDeviceSocketManager());
}

HWTEST_F(DslmMsgLibTest, ProcessSocketMessageReceivedTest, TestSize.Level0)
{
    DeviceSocketManager *inst = UtGetDeviceSocketManagerInstance();
    ASSERT_NE(inst, nullptr);

    {
        UtProcessSocketMessageReceived(nullptr, 0);
        uint8_t data[] = {};
        UtProcessSocketMessageReceived(data, 0);
    }
    {
        uint8_t *data = static_cast<uint8_t *>(MALLOC(UINT8_MAX));
        ASSERT_NE(data, nullptr);

        UtProcessSocketMessageReceived(data, 1); // will free the data.
        UtRemoveSocketNode(0, SHUTDOWN_REASON_UNKNOWN, false);
    }
    {
        uint8_t *data = static_cast<uint8_t *>(MALLOC(UINT8_MAX));
        ASSERT_NE(data, nullptr);
        QueueMsgData *queueData = reinterpret_cast<QueueMsgData *>(data);
        queueData->msgLen = (UINT8_MAX > sizeof(QueueMsgData)) ? UINT8_MAX - sizeof(QueueMsgData) : 0;

        UtProcessSocketMessageReceived(data, 1); // will free the data.
        UtRemoveSocketNode(0, SHUTDOWN_REASON_UNKNOWN, false);
    }
    {
        uint8_t *data = static_cast<uint8_t *>(MALLOC(UINT8_MAX + sizeof(QueueMsgData)));
        ASSERT_NE(data, nullptr);
        QueueMsgData *queueData = reinterpret_cast<QueueMsgData *>(data);
        queueData->msgLen = UINT8_MAX;

        UtProcessSocketMessageReceived(data, UINT8_MAX + sizeof(QueueMsgData)); // will free the data.
        UtRemoveSocketNode(0, SHUTDOWN_REASON_UNKNOWN, false);
    }
    {
        MessengerConfig config = {
            .pkgName = "pkg",
            .primarySockName = "pr",
            .secondarySockName = "",
            .threadCnt = 1,
            .messageReceiver = [](const DeviceIdentify *, const uint8_t *, uint32_t) { return 0; },
        };
        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_TRUE(ret);

        uint8_t *data = static_cast<uint8_t *>(MALLOC(UINT8_MAX + sizeof(QueueMsgData)));
        ASSERT_NE(data, nullptr);
        QueueMsgData *queueData = reinterpret_cast<QueueMsgData *>(data);
        queueData->msgLen = UINT8_MAX;

        UtProcessSocketMessageReceived(data, UINT8_MAX + sizeof(QueueMsgData)); // will free the data.
        UtRemoveSocketNode(0, SHUTDOWN_REASON_UNKNOWN, false);
        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
}

HWTEST_F(DslmMsgLibTest, OnSocketMessageReceivedTest, TestSize.Level0)
{
    {
        UtOnSocketMessageReceived(nullptr, nullptr, 0);
    }
    {
        DeviceIdentify idt {};
        UtOnSocketMessageReceived(&idt, nullptr, 0);
    }
    {
        DeviceIdentify idt {};
        MessengerConfig config = {
            .pkgName = "pkg",
            .primarySockName = "pr",
            .secondarySockName = "",
            .messageReceiver = [](const DeviceIdentify *, const uint8_t *, uint32_t) { return 0; },
        };

        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_TRUE(ret);
        uint8_t msg[UINT8_MAX] = {0};
        UtOnSocketMessageReceived(&idt, msg, UINT8_MAX);

        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
    {
        DeviceIdentify idt {};
        MessengerConfig config = {.pkgName = "pkg", .primarySockName = "pr", .secondarySockName = "", .threadCnt = 1};

        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_TRUE(ret);
        uint8_t msg[UINT8_MAX] = {0};
        UtOnSocketMessageReceived(&idt, msg, UINT8_MAX);

        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
}

HWTEST_F(DslmMsgLibTest, GetIdentityBySocketIdTest, TestSize.Level0)
{
    {
        auto ret = UtGetIdentityBySocketId(0, false, nullptr);
        EXPECT_FALSE(ret);
    }
    {
        DeviceIdentify idt {};
        auto ret = UtGetIdentityBySocketId(0, true, &idt);
        EXPECT_FALSE(ret);
    }
    {
        DeviceIdentify idt {};
        auto ret = UtGetIdentityBySocketId(0, false, &idt);
        EXPECT_FALSE(ret);
    }
}

HWTEST_F(DslmMsgLibTest, MessengerSendMsgToTest, TestSize.Level0)
{
    {
        MessengerSendMsgTo(0, nullptr, nullptr, 0);
    }
    {
        DeviceIdentify idt {};
        MessengerSendMsgTo(0, &idt, nullptr, 0);
    }
    {
        DeviceIdentify idt {};
        uint8_t data[UINT16_MAX] = {};
        MessengerSendMsgTo(0, &idt, data, 0);
    }
    {
        DeviceIdentify idt {};
        uint8_t data[UINT16_MAX] = {};
        MessengerSendMsgTo(0, &idt, data, (81920 * 4) + 1);
    }
    {
        DeviceIdentify idt {};
        uint8_t data[UINT16_MAX] = {0};
        MessengerSendMsgTo(0, &idt, data, UINT16_MAX);
    }
    {
        MessengerConfig config = {.pkgName = "pkg",
            .primarySockName = "pr",
            .secondarySockName = "se",
            .threadCnt = 1,
            .messageReceiver = [](const DeviceIdentify *, const uint8_t *, uint32_t) { return 0; },
        };
        auto ret = InitDeviceSocketManager(queue, &config);
        EXPECT_TRUE(ret);

        uint8_t msg[UINT8_MAX] = {0};
        {
            DeviceIdentify idt {.identity = {'a'}, .length = 1};
            MessengerSendMsgTo(0, &idt, msg, UINT8_MAX);
        }
        {
            DeviceIdentify idt {.identity = {'x'}, .length = 1};
            MessengerSendMsgTo(0, &idt, msg, UINT8_MAX);
        }
        EXPECT_TRUE(DeInitDeviceSocketManager());
    }
}

HWTEST_F(DslmMsgLibTest, CreateQueueMsgDataTest, TestSize.Level0)
{
    {
        auto *data = CreateQueueMsgData(nullptr, nullptr, 0, nullptr);
        EXPECT_EQ(data, nullptr);
    }
    {
        DeviceIdentify idt {};
        auto *data = CreateQueueMsgData(&idt, nullptr, 0, nullptr);
        EXPECT_EQ(data, nullptr);
    }
    {
        DeviceIdentify idt {};
        uint8_t msg[UINT8_MAX] = {0};
        auto *data = CreateQueueMsgData(&idt, msg, 0, nullptr);
        EXPECT_EQ(data, nullptr);
    }
    {
        DeviceIdentify idt {};
        uint8_t msg[UINT8_MAX] = {0};
        auto *data = CreateQueueMsgData(&idt, msg, UINT8_MAX, nullptr);
        EXPECT_EQ(data, nullptr);
    }
    {
        DeviceIdentify idt {};
        uint8_t msg[UINT8_MAX] = {0};
        uint32_t queueDataLen = 0;
        auto *data = CreateQueueMsgData(&idt, msg, UINT8_MAX, &queueDataLen);
        ASSERT_NE(data, nullptr);
        EXPECT_EQ(data->msgLen, UINT8_MAX);
        EXPECT_EQ(queueDataLen, UINT8_MAX + sizeof(QueueMsgData));
    }
}

HWTEST_F(DslmMsgLibTest, SocketShutDownTest, TestSize.Level0)
{
    MessengerConfig config = {.pkgName = "pkg", .primarySockName = "pr", .secondarySockName = "", .threadCnt = 1};
    auto ret = InitDeviceSocketManager(queue, &config);
    EXPECT_TRUE(ret);

    DeviceIdentify idt {.length = 1, .identity = {'a'}};

    char dummy[] = {'a', 0};
    PeerSocketInfo peer = {.name = dummy, .networkId = dummy};
    UtServerOnBind(1, peer);
    UtClientOnBind(1, &idt);

    UtCreateOrRestartSocketCloseTimerWithLock(0);
    UtCreateOrRestartSocketCloseTimerWithLock(1);

    UtServerOnShutdown(3, SHUTDOWN_REASON_UNKNOWN);
    UtClientOnShutdown(4, SHUTDOWN_REASON_UNKNOWN);
    UtServerOnShutdown(0, SHUTDOWN_REASON_UNKNOWN);
    UtClientOnShutdown(0, SHUTDOWN_REASON_UNKNOWN);
    UtServerOnShutdown(1, SHUTDOWN_REASON_UNKNOWN);
    UtClientOnShutdown(1, SHUTDOWN_REASON_UNKNOWN);
    EXPECT_TRUE(DeInitDeviceSocketManager());
}

HWTEST_F(DslmMsgLibTest, MessengerGetNetworkIdByDeviceIdentifyTest, TestSize.Level0)
{
    {
        auto ret = MessengerGetNetworkIdByDeviceIdentify(nullptr, nullptr, 0);
        EXPECT_FALSE(ret);
    }
    {
        DeviceIdentify idt {.length = 1, .identity = {'a'}};
        auto ret = MessengerGetNetworkIdByDeviceIdentify(&idt, nullptr, 0);
        EXPECT_FALSE(ret);
    }
    {
        DeviceIdentify idt {.length = 1, .identity = {'a'}};
        char id[UINT8_MAX] = {0};
        auto ret = MessengerGetNetworkIdByDeviceIdentify(&idt, id, 0);
        EXPECT_FALSE(ret);
    }
    {
        DeviceIdentify idt {.length = 1, .identity = {'a'}};
        char id[UINT8_MAX] = {0};
        auto ret = MessengerGetNetworkIdByDeviceIdentify(&idt, id, UINT8_MAX);
        EXPECT_FALSE(ret);
    }
}

HWTEST_F(DslmMsgLibTest, MessengerForEachDeviceProcessTest, TestSize.Level0)
{
    {
        MessengerForEachDeviceProcess(nullptr, nullptr);
    }
    {
        MessengerForEachDeviceProcess([](const DeviceIdentify *, int32_t, void *) { return 0; }, nullptr);
    }
    {
        auto &mock = DistributedHardware::DeviceManagerMock::Instance();
        EXPECT_CALL(mock, GetTrustedDeviceList).WillOnce(Return(1));
        MessengerForEachDeviceProcess([](const DeviceIdentify *, int32_t, void *) { return 0; }, nullptr);
    }
}

HWTEST_F(DslmMsgLibTest, UtTimerProcessWaitingTimeOutTest, TestSize.Level0)
{
    LOG_SetCallback(LogCallback);
    {
        UtTimerProcessWaitingTimeOut(nullptr);
    }
    {
        char id[UINT8_MAX] = {0};
        UtTimerProcessWaitingTimeOut(id);
        EXPECT_TRUE(g_errLog.find("SocketClosed") != std::string::npos);
    }
}

HWTEST_F(DslmMsgLibTest, UtCreateServerTest, TestSize.Level0)
{
    EXPECT_FALSE(UtCreateServer(nullptr));
}

HWTEST_F(DslmMsgLibTest, UtBindSync, TestSize.Level0)
{
    {
        EXPECT_FALSE(UtBindSync(0, nullptr));
    }
    {
        DeviceIdentify idt {};
        EXPECT_TRUE(UtBindSync(1, &idt));
    }
    {
        DeviceIdentify idt {};
        EXPECT_TRUE(UtBindSync(1, &idt));
    }
    {
        NiceMock<DslmMsgInterfaceMock> msgMock;
        ON_CALL(msgMock, Bind).WillByDefault([](int32_t, const QosTV[], uint32_t, const ISocketListener *) {
            return UINT16_MAX;
        });
        DeviceIdentify idt {};
        EXPECT_FALSE(UtBindSync(1, &idt));
    }
}

HWTEST_F(DslmMsgLibTest, UtGetClientNameTest, TestSize.Level0)
{
    {
        EXPECT_NE(0, UtGetClientName(nullptr, nullptr, 0, false));
    }
    {
        char name[UINT8_MAX] = {0};
        EXPECT_NE(0, UtGetClientName(name, nullptr, 0, false));
    }
    {
        char name[UINT8_MAX] = {0};
        char to[UINT8_MAX] = {0};
        EXPECT_EQ(0, UtGetClientName(name, to, 0, false));
    }
    {
        char name[UINT8_MAX] = {0};
        char to[UINT8_MAX] = {0};
        EXPECT_EQ(0, UtGetClientName(name, to, 0, true));
    }
}

HWTEST_F(DslmMsgLibTest, UtGetSocketBySocketListTest, TestSize.Level0)
{
    DeviceIdentify idt {};
    UtPushMsgDataToPendingList(0, nullptr, nullptr, 0);
    UtPushMsgDataToPendingList(0, &idt, nullptr, 0);

    EXPECT_FALSE(UtGetSocketBySocketList(nullptr, false, nullptr));

    EXPECT_FALSE(UtGetSocketBySocketList(&idt, false, nullptr));

    EXPECT_EQ(nullptr, UtCreateSocketNodeInfo(0, nullptr));
}

HWTEST_F(DslmMsgLibTest, MessengerGetDeviceIdentifyByNetworkId, TestSize.Level0)
{
    {
        EXPECT_FALSE(MessengerGetDeviceIdentifyByNetworkId(nullptr, nullptr));
    }
    {
        EXPECT_FALSE(MessengerGetDeviceIdentifyByNetworkId("a", nullptr));
    }
    {
        DeviceIdentify idt {};
        EXPECT_TRUE(MessengerGetDeviceIdentifyByNetworkId("a", &idt));
    }
}

HWTEST_F(DslmMsgLibTest, MessengerGetNetworkIdByDeviceIdentify, TestSize.Level0)
{
    {
        EXPECT_FALSE(MessengerGetNetworkIdByDeviceIdentify(nullptr, nullptr, 0));
    }
    {
        DeviceIdentify idt {};
        EXPECT_FALSE(MessengerGetNetworkIdByDeviceIdentify(&idt, nullptr, 0));
    }
}

HWTEST_F(DslmMsgLibTest, MessengerGetSelfDeviceIdentify, TestSize.Level0)
{
    {
        EXPECT_FALSE(MessengerGetSelfDeviceIdentify(nullptr, nullptr));
    }
    {
        DeviceIdentify idt {};
        EXPECT_FALSE(MessengerGetSelfDeviceIdentify(&idt, nullptr));
    }
    {
        DeviceIdentify idt {};
        int32_t level = 0;
        EXPECT_TRUE(MessengerGetSelfDeviceIdentify(&idt, &level));
    }
    {
        auto &mock = DistributedHardware::DeviceManagerMock::Instance();
        EXPECT_CALL(mock, GetLocalDeviceInfo).WillOnce(Return(1));

        DeviceIdentify idt {};
        int32_t level = 0;
        EXPECT_FALSE(MessengerGetSelfDeviceIdentify(&idt, &level));
    }
}

HWTEST_F(DslmMsgLibTest, MessengerGetDeviceOnlineStatus, TestSize.Level0)
{
    {
        EXPECT_FALSE(MessengerGetDeviceOnlineStatus(nullptr, nullptr));
    }
    {
        DeviceIdentify idt {.identity = {'a'}, .length = 1};
        EXPECT_FALSE(MessengerGetDeviceOnlineStatus(&idt, nullptr));
    }
    {
        DeviceIdentify idt {.identity = {'a'}, .length = 1};
        int32_t level = 0;
        EXPECT_FALSE(MessengerGetDeviceOnlineStatus(&idt, &level));
    }
}

HWTEST_F(DslmMsgLibTest, InitDeviceStatusManager, TestSize.Level0)
{
    {
        EXPECT_FALSE(InitDeviceStatusManager(nullptr, nullptr, nullptr));
    }

    {
        EXPECT_FALSE(InitDeviceStatusManager(queue, nullptr, nullptr));
    }

    {
        EXPECT_FALSE(InitDeviceStatusManager(queue, "??", nullptr));
    }

    {
        auto recv = [](const DeviceIdentify *devId, uint32_t status, int32_t level) -> int32_t { return 0; };
        EXPECT_TRUE(InitDeviceStatusManager(queue, "??", recv));
        EXPECT_TRUE(DeInitDeviceStatusManager());
    }
    {
        auto &mock = DistributedHardware::DeviceManagerMock::Instance();
        EXPECT_CALL(mock, InitDeviceManager).WillOnce(Return(1)).WillOnce(Return(0));
        auto recv = [](const DeviceIdentify *devId, uint32_t status, int32_t level) -> int32_t { return 0; };
        EXPECT_TRUE(InitDeviceStatusManager(queue, "??", recv));
    }
}
} // namespace DslmUnitTest
} // namespace Security
} // namespace OHOS