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

#ifndef DSLM_IPC_PROCESS_H
#define DSLM_IPC_PROCESS_H

#include "device_security_defines.h"
#include "samgr_lite.h"
#include "serializer.h"
#include "utils_dslm_list.h"
#include "utils_mutex.h"

int32_t DslmProcessGetDeviceSecurityLevel(IUnknown *iUnknown, IpcIo *req, IpcIo *reply);

typedef struct DslmRemoteStubListNode {
    ListNode node;
    uint64_t key;
    IpcIo *reply;
} DslmRemoteStubListNode;

typedef struct DslmRemoteStubList {
    DslmRemoteStubListNode *head;
    uint32_t size;
    Mutex *mutex;
} DslmRemoteStubList;
#endif // DSLM_IPC_PROCESS_H