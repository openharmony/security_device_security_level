/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dslm_fuzzer.h"

#include "parcel.h"
#include "securec.h"

#include "device_security_defines.h"
#include "device_security_level_callback_stub.h"
#include "dslm_credential.h"
#include "dslm_device_list.h"
#include "dslm_service.h"
#include "dslm_device_list.h"


#define CNT 1000
#define ITEMSTATE 4

extern "C" int32_t OnPeerMsgReceived(const DeviceIdentify *devId, const uint8_t *msg, uint32_t len);

namespace OHOS {
namespace Security {
namespace DeviceSecurityLevel {
namespace {
const uint8_t mockBuffer[DEVICE_ID_MAX_LEN] = {0};

DslmService g_dslmService(DEVICE_SECURITY_LEVEL_MANAGER_SA_ID, true);

void OnPeerMsgReceivedFuzzer(Parcel &parcel)
{
    SECURITY_LOG_INFO("begin");
    DeviceIdentify deviceIdentify = {};
    deviceIdentify.length = DEVICE_ID_MAX_LEN;
    const uint8_t *buffer = parcel.ReadBuffer(DEVICE_ID_MAX_LEN);
    if (buffer != nullptr) {
        (void)memcpy_s(deviceIdentify.identity, DEVICE_ID_MAX_LEN, buffer, DEVICE_ID_MAX_LEN);
    }

    static int cnt = 0;
    cnt++;
    if (cnt <= CNT) {
        DslmDeviceInfo *info = CreatOrGetDslmDeviceInfo(&deviceIdentify);
        if (info != nullptr) {
            info->machine.currState = parcel.ReadUint32() % ITEMSTATE;
        }
    }

    uint32_t a = parcel.ReadUint32() % 3;
    if (a == 0) {
        uint8_t jsonString[] = R"(
            {"message":0, "payload":111}
        )";
        OnPeerMsgReceived(&deviceIdentify, jsonString, sizeof(jsonString));
    } else if (a == 1) {
        uint8_t jsonString[] = R"(
            {"message":1, "payload":{"challenge":"0102030405060708"}}
        )";
        OnPeerMsgReceived(&deviceIdentify, jsonString, sizeof(jsonString));
    } else {
        uint8_t jsonString[] = R"(
            {"message":2, "payload":222}
        )";
        OnPeerMsgReceived(&deviceIdentify, jsonString, sizeof(jsonString));
    }
    SECURITY_LOG_INFO("end");
}

void OnRemoteRequestFuzzer(Parcel &parcel)
{
    SECURITY_LOG_INFO("begin");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDeviceSecurityLevel::GetDescriptor());

    /* DeviceIdentify */
    data.WriteUint32(parcel.ReadUint32());
    const uint8_t *buffer = parcel.ReadBuffer(DEVICE_ID_MAX_LEN);
    if (buffer == nullptr) {
        data.WriteBuffer(mockBuffer, DEVICE_ID_MAX_LEN);
    } else {
        data.WriteBuffer(buffer, DEVICE_ID_MAX_LEN);
    }

    /* option */
    data.WriteUint64(parcel.ReadUint64());
    data.WriteUint32(parcel.ReadUint32());
    data.WriteUint32(parcel.ReadUint32());

    sptr<IRemoteObject> callback = new (std::nothrow) DeviceSecurityLevelCallbackStub(
        [](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            SECURITY_LOG_INFO("DeviceSecurityLevelCallbackStub called");
            return 0;
        });
    /* callback */
    data.WriteRemoteObject(callback);
    /* cookie */
    data.WriteUint32(parcel.ReadUint32());

    g_dslmService.OnRemoteRequest(parcel.ReadUint32(), data, reply, option);
    SECURITY_LOG_INFO("end");
}

void DslmFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    if (parcel.ReadBool()) {
        OnPeerMsgReceivedFuzzer(parcel);
    } else {
        OnRemoteRequestFuzzer(parcel);
    }
}
} // namespace
} // namespace DeviceSecurityLevel
} // namespace Security
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int initCount = 0;
    if (initCount == 0) {
        const ProcessDslmCredFunctions func = {
            .initFunc = InitOhosDslmCred,
            .requestFunc = RequestOhosDslmCred,
            .verifyFunc = VerifyOhosDslmCred,
            .credTypeCnt = 2,
            .credTypeArray = { CRED_TYPE_STANDARD, CRED_TYPE_SMALL },
        };
        InitDslmCredentialFunctions(&func);
        initCount = 1;
    }
    OHOS::Security::DeviceSecurityLevel::DslmFuzzTest(data, size);
    return 0;
}
