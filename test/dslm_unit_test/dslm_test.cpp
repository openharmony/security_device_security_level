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

#include "dslm_test.h"

#include <chrono>
#include <condition_variable>
#include <gtest/gtest.h>
#include <iostream>
#include <mutex>
#include <thread>

#include "file_ex.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

#include "device_security_defines.h"
#include "device_security_info.h"

#include "dslm_core_defines.h"
#include "dslm_core_process.h"
#include "dslm_credential.h"
#include "dslm_crypto.h"
#include "dslm_device_list.h"
#include "dslm_fsm_process.h"
#include "dslm_messenger_wrapper.h"
#include "dslm_msg_interface_mock.h"
#include "dslm_msg_serialize.h"
#include "dslm_msg_utils.h"
#include "dslm_request_callback_mock.h"
#include "utils_datetime.h"

using namespace std;
using namespace std::chrono;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace DslmUnitTest {
void DslmTest::SetUpTestCase()
{
    // modify the device's systime to ensure that the certificate verification passes
    constexpr time_t YEAR_TIME_2022 = 1640966400;
    constexpr time_t YEAR_TIME_2022_VALID = 1648518888;
    struct timeval timeVal = {0};
    gettimeofday(&timeVal, nullptr);
    if (timeVal.tv_sec <= YEAR_TIME_2022) {
        timeVal.tv_sec = YEAR_TIME_2022_VALID;
        settimeofday(&timeVal, nullptr);
    }

    static const char *ACLS[] = {"ACCESS_IDS"};
    static const char *PERMS[] = {
        "ohos.permission.PLACE_CALL",
        "ohos.permission.ACCESS_IDS"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = nullptr,
        .perms = PERMS,
        .acls = ACLS,
        .processName = "dslm_service",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    SaveStringToFile("/sys/fs/selinux/enforce", "0");
}
void DslmTest::TearDownTestCase()
{
    SaveStringToFile("/sys/fs/selinux/enforce", "1");
}
void DslmTest::SetUp()
{
}
void DslmTest::TearDown()
{
}

static void BlockCheckDeviceStatus(const DeviceIdentify *device, uint32_t status, uint64_t millisec)
{
    static int sleepTick = 10;
    uint64_t cnt = millisec / static_cast<uint64_t>(sleepTick) + 1;
    do {
        const DslmDeviceInfo *info = GetDslmDeviceInfo(device);
        if (info == nullptr) {
            continue;
        }
        if (info->machine.currState == status) {
            break;
        }
        if (cnt == 0) {
            break;
        }
        this_thread::sleep_for(milliseconds(sleepTick));
        cnt--;
    } while (true);
}

HWTEST_F(DslmTest, BuildDeviceSecInfoRequest_case1, TestSize.Level0)
{
    uint64_t random = 0x0807060504030201;
    MessageBuff *msg = nullptr;
    // 0d196608 = 0x030000
    const char *except =
        "{\"message\":1,\"payload\":{\"version\":196608,\"challenge\":\"0102030405060708\",\"support\":[3000,2000]}}";
    int32_t ret = BuildDeviceSecInfoRequest(random, &msg);
    ASSERT_EQ(0, ret);
    EXPECT_STREQ(except, (const char *)msg->buff);
    FreeMessageBuff(msg);
}

HWTEST_F(DslmTest, BuildDeviceSecInfoResponse_case1, TestSize.Level0)
{
    uint64_t random = 0x0807060504030201;
    uint8_t info[] = {'a', 'b', 'c', 'd', 1, 3, 5, 7, 9};
    DslmCredBuff cred = {(CredType)3, 9, info};

    // 0d196608 = 0x030000
    const char *except = "{\"message\":2,\"payload\":{\"version\":196608,\"type\":3,\"challenge\":\"0102030405060708\","
                         "\"info\":\"YWJjZAEDBQcJ\"}}";

    MessageBuff *msg = nullptr;
    int32_t ret = BuildDeviceSecInfoResponse(random, (DslmCredBuff *)&cred, &msg);
    ASSERT_EQ(0, ret);

    EXPECT_STREQ(except, (const char *)msg->buff);
    FreeMessageBuff(msg);
}

HWTEST_F(DslmTest, ParseMessage_case1, TestSize.Level0)
{
    const char *message = "{\"message\":1,\"payload\":{\"version\":131072,\"challenge\":\"0102030405060708\"}}";
    const char *except = "{\"version\":131072,\"challenge\":\"0102030405060708\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    MessagePacket *packet = ParseMessage(&msg);
    ASSERT_NE(nullptr, packet);

    EXPECT_EQ(1, (int32_t)packet->type);
    EXPECT_STREQ(except, (const char *)packet->payload);

    FreeMessagePacket(packet);
}

HWTEST_F(DslmTest, ParseMessage_case2, TestSize.Level0)
{
    const char *message = "{\"mege\":1,\"payload\":{\"version\":131072,\"challenge\":\"0102030405060708\"}}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    MessagePacket *packet = ParseMessage(&msg);
    EXPECT_EQ(nullptr, packet);
    FreeMessagePacket(packet);
}

HWTEST_F(DslmTest, ParseMessage_case3, TestSize.Level0)
{
    const char *message = "{\"message\":1,\"pay\":{\"version\":131072,\"challenge\":\"0102030405060708\"}}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    MessagePacket *packet = ParseMessage(&msg);
    EXPECT_EQ(nullptr, packet);
    FreeMessagePacket(packet);
}

HWTEST_F(DslmTest, ParseMessage_case4, TestSize.Level0)
{
    const MessageBuff *buff = NULL;
    EXPECT_EQ(NULL, ParseMessage(buff));
}

HWTEST_F(DslmTest, ParseMessage_case5, TestSize.Level0)
{
    uint8_t *message = NULL;
    uint32_t messageLen = 0;
    MessageBuff msg = {.length = messageLen, .buff = message};

    EXPECT_EQ(NULL, ParseMessage(&msg));
}

HWTEST_F(DslmTest, ParseMessage_case6, TestSize.Level0)
{
    uint8_t message[] = {'1', '2'};
    uint32_t messageLen = 2;
    MessageBuff msg = {.length = messageLen, .buff = message};
    EXPECT_EQ(NULL, ParseMessage(&msg));
}

HWTEST_F(DslmTest, ParseMessage_case7, TestSize.Level0)
{
    uint8_t message[] = {1, 2, 0};
    uint32_t messageLen = 3;
    MessageBuff msg = {.length = messageLen, .buff = message};
    EXPECT_EQ(NULL, ParseMessage(&msg));
}

HWTEST_F(DslmTest, ParseDeviceSecInfoRequest_case1, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challenge\":\"010203040a0b0c0d\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    RequestObject obj;
    (void)memset_s(&obj, sizeof(RequestObject), 0, sizeof(RequestObject));

    // 3351057 = 0x332211
    int32_t ret = ParseDeviceSecInfoRequest(&msg, &obj);
    EXPECT_EQ(0, ret);

    EXPECT_EQ((uint32_t)0x332211, obj.version);
    EXPECT_EQ((uint64_t)0x0d0c0b0a04030201, obj.challenge);
    EXPECT_EQ((uint32_t)0, obj.arraySize);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoRequest_case2, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challenge\":\"z\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    RequestObject obj;
    (void)memset_s(&obj, sizeof(RequestObject), 0, sizeof(RequestObject));

    int32_t ret = ParseDeviceSecInfoRequest(&msg, &obj);
    EXPECT_EQ(ERR_NO_CHALLENGE, ret);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoRequest_case3, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challenge\":1}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    RequestObject obj;
    (void)memset_s(&obj, sizeof(RequestObject), 0, sizeof(RequestObject));
    int32_t ret = ParseDeviceSecInfoRequest(&msg, &obj);
    EXPECT_EQ(ERR_NO_CHALLENGE, ret);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoRequest_case4, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challssenge\":\"z\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    RequestObject obj;
    (void)memset_s(&obj, sizeof(RequestObject), 0, sizeof(RequestObject));
    int32_t ret = ParseDeviceSecInfoRequest(&msg, &obj);
    EXPECT_EQ(ERR_NO_CHALLENGE, ret);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoRequest_case5, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challenge\":\"010203040a0b0c0d\",\"support\":[33,44,55]}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    RequestObject obj;
    (void)memset_s(&obj, sizeof(RequestObject), 0, sizeof(RequestObject));

    // 3351057 = 0x332211
    int32_t ret = ParseDeviceSecInfoRequest(&msg, &obj);
    EXPECT_EQ(0, ret);
    EXPECT_EQ((uint32_t)0x332211, obj.version);
    EXPECT_EQ((uint64_t)0x0d0c0b0a04030201, obj.challenge);
    // add support
    EXPECT_EQ((uint32_t)3, obj.arraySize);
    EXPECT_EQ((uint32_t)33, obj.credArray[0]);
    EXPECT_EQ((uint32_t)44, obj.credArray[1]);
    EXPECT_EQ((uint32_t)55, obj.credArray[2]);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoRequest_case6, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challenge\":\"010203040a0b0c0d\",\"support\":[]}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    RequestObject obj;
    (void)memset_s(&obj, sizeof(RequestObject), 0, sizeof(RequestObject));

    // 3351057 = 0x332211
    int32_t ret = ParseDeviceSecInfoRequest(&msg, &obj);
    EXPECT_EQ(0, ret);
    EXPECT_EQ((uint32_t)0x332211, obj.version);
    EXPECT_EQ((uint64_t)0x0d0c0b0a04030201, obj.challenge);
    // add support
    EXPECT_EQ((uint32_t)0, obj.arraySize);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoResponse_case1, TestSize.Level0)
{
    const char *message = "{\"version\":131072,\"challenge\":\"3C1F21EE53D3C4E2\",\"type\":2,\"info\":"
                          "\"SkFERS1BTDAwOjg3QUQyOEQzQjFCLi4u\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    uint64_t challenge;
    uint32_t version;
    DslmCredBuff *cred = nullptr;

    // 131072 = 0x020000
    int32_t ret = ParseDeviceSecInfoResponse(&msg, &challenge, &version, &cred);
    EXPECT_EQ(0, ret);
    EXPECT_EQ((uint32_t)0x020000, version);

    EXPECT_EQ((uint64_t)0xE2C4D353EE211F3C, challenge);

    const char *except = "JADE-AL00:87AD28D3B1B...";
    EXPECT_NE(nullptr, cred);
    EXPECT_EQ(2, (int32_t)cred->type);
    EXPECT_EQ(strlen(except), cred->credLen);
    EXPECT_EQ(0, strncmp(except, (const char *)cred->credVal, cred->credLen));
    DestroyDslmCred(cred);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoResponse_case2, TestSize.Level0)
{
    const char *message = "{\"version\":3351057,\"challssenge\":\"z\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    uint64_t challenge;
    uint32_t ver;
    DslmCredBuff *cred = nullptr;

    int32_t ret = ParseDeviceSecInfoResponse(&msg, &challenge, &ver, &cred);
    EXPECT_EQ(ERR_NO_CHALLENGE, ret);
}

HWTEST_F(DslmTest, ParseDeviceSecInfoResponse_case3, TestSize.Level0)
{
    const char *message =
        "{\"version\":131072,\"challenge\":\"3C1F21EE53D3C4E2\",\"type\":2,\"infod\":\"JADE-AL00:87AD28D3B1B...\"}";

    uint32_t messageLen = strlen(message) + 1;
    MessageBuff msg = {.length = messageLen, .buff = (uint8_t *)message};

    uint64_t challenge;
    uint32_t ver;
    DslmCredBuff *cred = nullptr;

    int32_t ret = ParseDeviceSecInfoResponse(&msg, &challenge, &ver, &cred);
    EXPECT_EQ(ERR_NO_CRED, ret);
}

HWTEST_F(DslmTest, RandomValue_case1, TestSize.Level0)
{
    RandomValue rand1 = {0, {0}};
    (void)memset_s(&rand1, sizeof(RandomValue), 0, sizeof(RandomValue));
    GenerateRandom(&rand1, sizeof(uint64_t));

    RandomValue rand2 = {0, {0}};
    (void)memset_s(&rand2, sizeof(RandomValue), 0, sizeof(RandomValue));
    GenerateRandom(&rand2, sizeof(uint64_t));

    EXPECT_EQ(sizeof(uint64_t), rand1.length);
    EXPECT_EQ(sizeof(uint64_t), rand2.length);

    EXPECT_GT(rand1.value[0] + rand1.value[1] + rand1.value[2] + rand1.value[3], 0);
    EXPECT_EQ(rand1.value[31] + rand1.value[30] + rand1.value[29] + rand1.value[28], 0);
    EXPECT_NE(0, memcmp(rand1.value, rand2.value, sizeof(uint64_t)));
}

HWTEST_F(DslmTest, RandomValue_case2, TestSize.Level0)
{
    RandomValue rand = {0, {0}};
    (void)memset_s(&rand, sizeof(RandomValue), 0, sizeof(RandomValue));

    GenerateRandom(&rand, 1024);
    EXPECT_EQ(RAMDOM_MAX_LEN, (int32_t)rand.length);

    GenerateRandom(nullptr, 1024);
}

HWTEST_F(DslmTest, GetMillisecondSinceBoot_case1, TestSize.Level0)
{
    uint64_t tick = 100;
    uint64_t start = GetMillisecondSinceBoot();
    EXPECT_GT(start, 0U);
    this_thread::sleep_for(milliseconds(tick));
    uint64_t end = GetMillisecondSinceBoot();
    EXPECT_GT(end, 0U);

    EXPECT_GT(end - start, tick - 10);
    EXPECT_LT(end - start, tick + 10);
}

HWTEST_F(DslmTest, GetMillisecondSince1970_case1, TestSize.Level0)
{
    uint64_t tick = 100;
    uint64_t start = GetMillisecondSince1970();
    EXPECT_GT(start, 0U);
    this_thread::sleep_for(milliseconds(tick));
    uint64_t end = GetMillisecondSince1970();
    EXPECT_GT(end, 0U);

    EXPECT_GT(end - start, tick - 10);
    EXPECT_LT(end - start, tick + 10);
}

HWTEST_F(DslmTest, GetDateTime_case1, TestSize.Level0)
{
    {
        DateTime date;
        EXPECT_TRUE(GetDateTimeByMillisecondSince1970(GetMillisecondSince1970(), &date));
    }
    {
        DateTime date;
        EXPECT_TRUE(GetDateTimeByMillisecondSinceBoot(GetMillisecondSinceBoot(), &date));
    }
}

HWTEST_F(DslmTest, OhosDslmCred_case1, TestSize.Level0)
{
    const DeviceIdentify identify = {DEVICE_ID_MAX_LEN, {0}};
    RequestObject object;

    object.arraySize = 1;
    object.credArray[0] = CRED_TYPE_STANDARD;
    object.challenge = 0x1234567812345678;
    object.version = 0x112234;

    DslmCredBuff *cred = nullptr;

    int32_t ret = DefaultRequestDslmCred(&identify, &object, &cred);
    ASSERT_EQ(SUCCESS, (int32_t)ret);

    DslmCredInfo info;
    (void)memset_s(&info, sizeof(DslmCredInfo), 0, sizeof(DslmCredInfo));

    ret = DefaultVerifyDslmCred(&identify, object.challenge, cred, &info);
    EXPECT_EQ(SUCCESS, ret);
    EXPECT_GE(info.credLevel, (uint32_t)1);

    DestroyDslmCred(cred);
}

HWTEST_F(DslmTest, OnRequestDeviceSecLevelInfo_case1, TestSize.Level0)
{
    const DeviceIdentify device = {DEVICE_ID_MAX_LEN, {'a', 'b', 'c', 'd', 'e', 'f', 'g'}};

    const RequestOption option = {
        .challenge = 0xffffffffffffffff,
        .timeout = 2,
    };

    {
        uint32_t cookie = 1234;
        DslmRequestCallbackMock mockCallback;
        EXPECT_CALL(mockCallback, RequestCallback(_, _, _)).Times(Exactly(0));
        int32_t ret = OnRequestDeviceSecLevelInfo(&device, &option, 0, cookie, DslmRequestCallbackMock::MockedCallback);
        EXPECT_EQ((int32_t)ret, ERR_MSG_NOT_INIT);
    }

    {
        uint32_t cookie = 5678;
        DslmMsgInterfaceMock mockMsg;
        DslmRequestCallbackMock mockCallback;
        EXPECT_CALL(mockMsg, IsMessengerReady(_)).Times(AtLeast(1));
        EXPECT_CALL(mockMsg, GetDeviceOnlineStatus(_, _, _)).Times(AtLeast(1)).WillRepeatedly(Return(false));
        EXPECT_CALL(mockCallback, RequestCallback(_, _, _)).Times(Exactly(0));
        int32_t ret = OnRequestDeviceSecLevelInfo(&device, &option, 0, cookie, DslmRequestCallbackMock::MockedCallback);
        EXPECT_EQ((int32_t)ret, ERR_NOEXIST_DEVICE);

        EXPECT_CALL(mockMsg, SendMsgTo(_, _, _, _, _)).Times(AtLeast(2));
        mockMsg.MakeMsgLoopback();
        mockMsg.MakeDeviceOnline(&device);
        BlockCheckDeviceStatus(&device, STATE_SUCCESS, 10000);
        mockMsg.MakeDeviceOffline(&device);
    }

    {
        uint32_t cookie = 0xabcd;
        DslmMsgInterfaceMock mockMsg;
        EXPECT_CALL(mockMsg, IsMessengerReady(_)).Times(AtLeast(1));
        EXPECT_CALL(mockMsg, GetDeviceOnlineStatus(_, _, _)).Times(AtLeast(1)).WillRepeatedly(Return(true));
        EXPECT_CALL(mockMsg, SendMsgTo(_, _, _, _, _)).Times(Exactly(1));
        DslmRequestCallbackMock mockCallback;
        auto IsRightLevel = [](const DslmCallbackInfo *info) { return info->level >= 1; };
        EXPECT_CALL(mockCallback, RequestCallback(cookie, 0, Truly(IsRightLevel))).Times(Exactly(1));

        int32_t ret = OnRequestDeviceSecLevelInfo(&device, &option, 0, cookie, DslmRequestCallbackMock::MockedCallback);
        EXPECT_EQ(ret, (int32_t)0);
        mockMsg.MakeDeviceOffline(&device);
    }
}

HWTEST_F(DslmTest, OnRequestDeviceSecLevelInfo_case2, TestSize.Level0)
{
    const DeviceIdentify device = {DEVICE_ID_MAX_LEN, {'a'}};
    const RequestOption option = {
        .challenge = 0xffabcdffffffffee,
        .timeout = 2,
        .extra = 0,
    };

    DslmMsgInterfaceMock mockMsg;
    EXPECT_CALL(mockMsg, IsMessengerReady(_)).Times(AtLeast(1));
    EXPECT_CALL(mockMsg, GetDeviceOnlineStatus(_, _, _)).Times(AtLeast(1)).WillRepeatedly(Return(true));
    auto isSendRequestOut = [](const uint8_t *message) {
        const char *prefix = "{\"message\":1,\"payload\":{\"version\":196608,\"challenge\":\"";
        string msg = string((char *)message);
        EXPECT_EQ((int)msg.rfind(prefix, 0), 0);
        return true;
    };

    uint32_t cookie = 0x4567;
    EXPECT_CALL(mockMsg, SendMsgTo(_, _, _, Truly(isSendRequestOut), _)).Times(AtLeast(1)).WillRepeatedly(Return(true));
    int32_t ret = OnRequestDeviceSecLevelInfo(&device, &option, 0, cookie, DslmRequestCallbackMock::MockedCallback);
    EXPECT_EQ((int32_t)ret, (int32_t)0);
    mockMsg.MakeDeviceOffline(&device);
}

HWTEST_F(DslmTest, OnRequestDeviceSecLevelInfo_case3, TestSize.Level0)
{
    DslmMsgInterfaceMock mockMsg;
    DslmRequestCallbackMock mockCallback;

    EXPECT_CALL(mockMsg, IsMessengerReady(_)).Times(AtLeast(1));
    EXPECT_CALL(mockMsg, GetDeviceOnlineStatus(_, _, _)).Times(AtLeast(1)).WillRepeatedly(Return(true));
    EXPECT_CALL(mockMsg, SendMsgTo(_, _, _, _, _)).Times(AtLeast(1)).WillRepeatedly(Return(true));

    mutex mtx;
    condition_variable cv;
    int32_t cnt = 0;
    const time_point<system_clock> start = system_clock::now();
    const int32_t reqTimes = 3;

    uint32_t cookies[] = {0, 0x1234, 0x5678, 0xabcd};
    uint32_t timeouts[] = {0, 1, 3, 5};

    auto checkCookie = [&mtx, &cv, &cnt, &start, &cookies, &timeouts](uint32_t cookie) {
        unique_lock<mutex> lck(mtx);
        cnt++;
        cv.notify_one();
        time_point<system_clock> curr = system_clock::now();
        auto cost = duration_cast<seconds>(curr - start).count();
        EXPECT_EQ(cookie, cookies[cnt]);
        EXPECT_EQ(cost, timeouts[cnt]);
        return true;
    };

    EXPECT_CALL(mockCallback, RequestCallback(Truly(checkCookie), ERR_TIMEOUT, _)).Times(Exactly(3));

    const DeviceIdentify device = {DEVICE_ID_MAX_LEN, {'a', 'b', 'c', 'd', 'e', 'f', 'a', 'b'}};
    RequestOption option;
    for (int i = 1; i <= reqTimes; i++) {
        option.timeout = timeouts[i];
        int32_t ret =
            OnRequestDeviceSecLevelInfo(&device, &option, i, cookies[i], DslmRequestCallbackMock::MockedCallback);
        EXPECT_EQ((int32_t)ret, (int32_t)0);
    }

    unique_lock<mutex> lck(mtx);
    cv.wait(lck, [&cnt]() { return (cnt == reqTimes); });
    mockMsg.MakeDeviceOffline(&device);
}

HWTEST_F(DslmTest, OnPeerMsgRequestInfoReceived_case1, TestSize.Level0)
{
    const char *input = "{\"version\":65536,\"challenge\":\"0102030405060708\"}";
    uint32_t len = strlen(input) + 1;

    const DeviceIdentify device = {DEVICE_ID_MAX_LEN, {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'}};

    DslmMsgInterfaceMock mockMsg;

    auto isSendResponseOut = [](const uint8_t *message) {
        const string msg = string((char *)message);
        EXPECT_EQ((int)msg.find("{\"message\":2,\"payload\":{"), 0);
        EXPECT_GT((int)msg.find("\"version\":"), 0);
        EXPECT_GT((int)msg.find("\"challenge\":"), 0);
        EXPECT_GT((int)msg.find("\"type\":"), 0);
        EXPECT_GT((int)msg.find("\"info\":"), 0);
        return true;
    };

    EXPECT_CALL(mockMsg, SendMsgTo(_, _, _, Truly(isSendResponseOut), _)).Times(Exactly(1));

    int32_t ret = OnPeerMsgRequestInfoReceived(&device, (const uint8_t *)input, len);
    EXPECT_EQ(0, (int32_t)ret);
}

HWTEST_F(DslmTest, OnPeerMsgResponseInfoReceived_case2, TestSize.Level0)
{
    const char *input = "{\"version\":65536,\"type\":0,\"challenge\":\"EEFFFFFFFFCDABFF\",\"info\":"
                        "\"MDAwMTAyMDMwNDA1MDYwNzA4MDkwQTBCMEMwRDBFMEYxMDExMTIxMzE0MTUxNkFBQkJDQ0RE\"}";
    uint32_t len = strlen(input) + 1;

    DeviceIdentify device = {8, {'a', 'b', 'c', 'd', 'e', 'f', 'g'}};

    int32_t ret = OnPeerMsgResponseInfoReceived(&device, (const uint8_t *)input, len);
    EXPECT_EQ(ERR_NOEXIST_DEVICE, (int32_t)ret);
}

HWTEST_F(DslmTest, InitSelfDeviceSecureLevel_case1, TestSize.Level0)
{
    const DeviceIdentify device = {DEVICE_ID_MAX_LEN, {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'}};
    DslmDeviceInfo *info = GetDslmDeviceInfo(&device);
    EXPECT_EQ(nullptr, info);

    DslmMsgInterfaceMock mockMsg;
    mockMsg.MakeSelfDeviceId(&device);
    mockMsg.MakeMsgLoopback();
    EXPECT_CALL(mockMsg, GetSelfDeviceIdentify(_, _, _)).Times(AtLeast(1));
    InitSelfDeviceSecureLevel();

    info = GetDslmDeviceInfo(&device);
    ASSERT_NE(nullptr, info);
    EXPECT_GE(info->credInfo.credLevel, (uint32_t)1);
    mockMsg.MakeDeviceOffline(&device);
}

HWTEST_F(DslmTest, InitSelfDeviceSecureLevel_case2, TestSize.Level0)
{
    const DeviceIdentify device = {DEVICE_ID_MAX_LEN, {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'}};

    DslmDeviceInfo *info = GetDslmDeviceInfo(&device);
    EXPECT_EQ(nullptr, info);

    DslmMsgInterfaceMock mockMsg;
    EXPECT_CALL(mockMsg, SendMsgTo(_, _, _, _, _)).Times(Exactly(6));
    mockMsg.MakeDeviceOnline(&device);

    info = GetDslmDeviceInfo(&device);
    ASSERT_NE(nullptr, info);
    EXPECT_EQ((uint32_t)1, info->queryTimes);
    EXPECT_EQ((uint32_t)STATE_WAITING_CRED_RSP, info->machine.currState);

    BlockCheckDeviceStatus(&device, STATE_SUCCESS, 5000);
    EXPECT_EQ((uint32_t)STATE_FAILED, info->machine.currState);
    EXPECT_LT((uint32_t)5, info->queryTimes);
    mockMsg.MakeDeviceOffline(&device);
}

HWTEST_F(DslmTest, InnerKitsTest_case1, TestSize.Level0)
{
    DeviceIdentify device = {DEVICE_ID_MAX_LEN, {0}};

    DeviceSecurityInfo *info = NULL;
    int32_t ret = RequestDeviceSecurityInfo(&device, NULL, &info);
    EXPECT_EQ(ret, 0);
    int32_t level = 0;
    ret = GetDeviceSecurityLevelValue(info, &level);
    FreeDeviceSecurityInfo(info);
    EXPECT_EQ(ret, 0);
    EXPECT_GE(level, 1);
}

static int32_t g_cnt = 0;
static mutex g_mtx;
static condition_variable g_cv;

void TestDeviceSecurityInfoCallback(const DeviceIdentify *identify, struct DeviceSecurityInfo *info)
{
    unique_lock<mutex> lck(g_mtx);
    int32_t level = 0;
    int32_t ret = GetDeviceSecurityLevelValue(info, &level);
    FreeDeviceSecurityInfo(info);
    EXPECT_EQ(ret, 0);
    EXPECT_GE(level, 1);
    g_cnt++;
    g_cv.notify_one();
}

HWTEST_F(DslmTest, InnerKitsTest_case2, TestSize.Level0)
{
    DeviceIdentify device = {DEVICE_ID_MAX_LEN, {0}};

    g_cnt = 0;
    int ret = RequestDeviceSecurityInfoAsync(&device, NULL, TestDeviceSecurityInfoCallback);
    EXPECT_EQ(ret, 0);

    ret = RequestDeviceSecurityInfoAsync(&device, NULL, TestDeviceSecurityInfoCallback);
    EXPECT_EQ(ret, 0);

    ret = RequestDeviceSecurityInfoAsync(&device, NULL, TestDeviceSecurityInfoCallback);
    EXPECT_EQ(ret, 0);

    unique_lock<mutex> lck(g_mtx);
    g_cv.wait_for(lck, std::chrono::milliseconds(2000), []() { return (g_cnt == 3); });
    EXPECT_EQ(g_cnt, 3);
}

HWTEST_F(DslmTest, InnerKitsTest_case3, TestSize.Level0)
{
    DeviceIdentify device = {DEVICE_ID_MAX_LEN, {0}};
    (void)memset_s(device.identity, DEVICE_ID_MAX_LEN, 'F', DEVICE_ID_MAX_LEN);
    DeviceSecurityInfo *info = NULL;
    int32_t ret = RequestDeviceSecurityInfo(&device, NULL, &info);
    EXPECT_EQ(ret, ERR_NOEXIST_DEVICE);
}
} // namespace DslmUnitTest
} // namespace Security
} // namespace OHOS
