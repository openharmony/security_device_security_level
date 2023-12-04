/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DSLM_INNER_PROCESS_H
#define DSLM_INNER_PROCESS_H

#include "device_security_defines.h"
#include "device_security_level_defines.h"

#include "samgr_lite.h"
#include "utils_dslm_list.h"
#include "utils_mutex.h"

typedef struct DslmAsyncCallParams {
    const DeviceIdentify *identity;
    const RequestOption *option;
    uint32_t cookie;
} DslmAsyncCallParams;

typedef struct DslmRemoteStubListNode {
    ListNode node;
    uint64_t key;
    DeviceSecurityInfoCallback *callback;
    const DeviceIdentify *identify;
} DslmRemoteStubListNode;

typedef struct DslmRemoteStubList {
    DslmRemoteStubListNode *head;
    uint32_t size;
    Mutex *mutex;
} DslmRemoteStubList;

int32_t DslmProcessGetDeviceSecurityLevel(IUnknown *iUnknown, DslmAsyncCallParams *req,
    DeviceSecurityInfoCallback callback);
#endif // DSLM_INNER_PROCESS_H