/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "device_security_level_defines.h"
#include "dslm_bigdata.h"
#include "dslm_core_defines.h"
#include "dslm_core_process.h"
#include "dslm_credential.h"
#include "dslm_crypto.h"
#include "dslm_device_list.h"
#include "dslm_fsm_process.h"
#include "dslm_hidumper.h"
#include "dslm_hievent.h"
#include "dslm_inner_process.h"
#include "dslm_memory_mock.h"
#include "dslm_messenger_wrapper.h"
#include "dslm_msg_serialize.h"
#include "dslm_msg_utils.h"
#include "dslm_ohos_request.h"
#include "dslm_ohos_verify.h"
#include "dslm_request_callback_mock.h"
#include "dslm_rpc_process.h"
#include "external_interface_adapter.h"
#include "hks_adapter.h"
#include "hks_type.h"
#include "messenger_device_socket_manager.h"
#include "messenger_device_status_manager.h"
#include "messenger_impl.h"
#include "utils_datetime.h"
#include "utils_mem.h"
#include "utils_timer.h"
#include "utils_tlv.h"
#include "utils_work_queue.h"

using namespace std;
using namespace std::chrono;
using namespace testing;
using namespace testing::ext;

typedef struct Messenger {
    uint32_t magicHead;
    WorkQueue *processQueue;
} Messenger;

#define MESSENGER_MAGIC_HEAD 0x1234abcd

namespace OHOS {
namespace Security {
namespace DslmUnitTest {
void DslmTest::SetUpTestCase()
{
}

void DslmTest::TearDownTestCase()
{
}

void DslmTest::SetUp()
{
}

void DslmTest::TearDown()
{
}

HWTEST_F(DslmTest, CreateMessengerImpl_case1, TestSize.Level0)
{
    const MessengerConfig config = {};

    Messenger *ret = CreateMessengerImpl(&config);
    EXPECT_EQ(nullptr, ret);

    ret = CreateMessengerImpl(nullptr);
    EXPECT_EQ(nullptr, ret);
}

HWTEST_F(DslmTest, IsMessengerReadyImpl_case1, TestSize.Level0)
{
    const Messenger messenger = {MESSENGER_MAGIC_HEAD, nullptr};
    const Messenger failedMessenger = {0, nullptr};

    bool ret = IsMessengerReadyImpl(&messenger);
    EXPECT_EQ(true, ret);

    ret = IsMessengerReadyImpl(&failedMessenger);
    EXPECT_EQ(false, ret);

    ret = IsMessengerReadyImpl(nullptr);
    EXPECT_EQ(false, ret);
}

HWTEST_F(DslmTest, SendMsgToImpl_case1, TestSize.Level0)
{
    const Messenger messenger = {MESSENGER_MAGIC_HEAD, nullptr};
    const Messenger failedMessenger = {0, nullptr};
    uint64_t transNo = 0;
    const DeviceIdentify devId = {DEVICE_ID_MAX_LEN, {0}};
    const uint8_t msg[] = {'1', '2'};
    uint32_t msgLen = 0;

    SendMsgToImpl(&messenger, transNo, &devId, msg, msgLen);

    SendMsgToImpl(nullptr, transNo, &devId, msg, msgLen);

    SendMsgToImpl(&failedMessenger, transNo, &devId, msg, msgLen);

    uint32_t ret = InitService();
    EXPECT_EQ(ERR_MSG_NOT_INIT, ret);
}

HWTEST_F(DslmTest, GetDeviceOnlineStatusImpl_case1, TestSize.Level0)
{
    const Messenger messenger = {MESSENGER_MAGIC_HEAD, nullptr};
    const Messenger failedMessenger = {0, nullptr};
    const DeviceIdentify devId = {DEVICE_ID_MAX_LEN, {0}};
    int32_t level = 0;

    bool ret = GetDeviceOnlineStatusImpl(&messenger, &devId, &level);
    EXPECT_EQ(false, ret);

    ret = GetDeviceOnlineStatusImpl(nullptr, &devId, &level);
    EXPECT_EQ(false, ret);

    ret = GetDeviceOnlineStatusImpl(&messenger, nullptr, &level);
    EXPECT_EQ(false, ret);

    ret = GetDeviceOnlineStatusImpl(&failedMessenger, &devId, &level);
    EXPECT_EQ(false, ret);
}

HWTEST_F(DslmTest, GetSelfDeviceIdentifyImpl_case1, TestSize.Level0)
{
    const Messenger messenger = {MESSENGER_MAGIC_HEAD, nullptr};
    const Messenger failedMessenger = {0, nullptr};
    DeviceIdentify devId = {DEVICE_ID_MAX_LEN, {0}};
    int32_t level = 0;

    bool ret = GetSelfDeviceIdentifyImpl(&messenger, &devId, &level);
    EXPECT_EQ(true, ret);

    ret = GetSelfDeviceIdentifyImpl(nullptr, &devId, &level);
    EXPECT_EQ(false, ret);

    ret = GetSelfDeviceIdentifyImpl(&messenger, nullptr, &level);
    EXPECT_EQ(false, ret);

    ret = GetSelfDeviceIdentifyImpl(&failedMessenger, &devId, &level);
    EXPECT_EQ(false, ret);
}

HWTEST_F(DslmTest, GetDeviceStatisticInfoImpl_case1, TestSize.Level0)
{
    const Messenger messenger = {MESSENGER_MAGIC_HEAD, nullptr};
    const Messenger failedMessenger = {0, nullptr};
    DeviceIdentify devId = {DEVICE_ID_MAX_LEN, {0}};
    const DeviceProcessor processor = nullptr;
    void *para = nullptr;
    StatisticInformation info = {};

    ForEachDeviceProcessImpl(&messenger, processor, para);

    ForEachDeviceProcessImpl(nullptr, processor, para);

    ForEachDeviceProcessImpl(&failedMessenger, processor, para);

    bool ret = GetDeviceStatisticInfoImpl(&messenger, &devId, &info);
    EXPECT_EQ(true, ret);

    ret = GetDeviceStatisticInfoImpl(&failedMessenger, &devId, &info);
    EXPECT_EQ(false, ret);

    ret = GetDeviceStatisticInfoImpl(nullptr, &devId, &info);
    EXPECT_EQ(false, ret);
}
} // namespace DslmUnitTest
} // namespace Security
} // namespace OHOS