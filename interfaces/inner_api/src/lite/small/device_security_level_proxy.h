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

#ifndef DEVICE_SECURITY_LEVEL_PROXY
#define DEVICE_SECURITY_LEVEL_PROXY

#include "iproxy_client.h"
#include "samgr_lite.h"

#include "device_security_defines.h"

#define DEFAULT_KEEP_LEN 45
#define MAX_KEEP_LEN 300

typedef struct DslmClientProxy {
    INHERIT_CLIENT_IPROXY;
    BOOL(*DslmIpcAsyncCall)
    (IUnknown *iUnknown, const DeviceIdentify identify, const RequestOption option, uint32_t cookie,
        DeviceSecurityInfoCallback callback);
} DslmClientProxy;

typedef struct DslmClientEntry {
    INHERIT_IUNKNOWNENTRY(DslmClientProxy);
} DslmClientEntry;

struct DslmCallbackHolder {
    DeviceIdentify identity;
    DeviceSecurityInfoCallback *callback;
};

#endif // DEVICE_SECURITY_LEVEL_PROXY