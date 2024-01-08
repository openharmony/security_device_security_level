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

#include "dslm_inner_process.h"

#include "dslm_callback_info.h"
#include "dslm_core_process.h"
#include "securec.h"
#include "utils_dslm_list.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_mutex.h"

#define DFT_TIMEOUT 45
const uint32_t MAX_TIMEOUT = 60;
const uint32_t MIN_TIMEOUT = 1;
const uint32_t WARNING_GATE = 64;
const uint32_t COOKIE_SHIFT = 32;
const uint32_t SINGLE_OWNER = 7;

static DslmRemoteStubList *GetRemoteStubList(void)
{
    static DslmRemoteStubListNode head = {.node = INIT_LIST(head.node), .key = 0, .callback = NULL, .identify = NULL};
    static Mutex mutex = INITED_MUTEX;
    static DslmRemoteStubList stubList = {.head = &head, .size = 0, .mutex = &mutex};
    return &stubList;
}

static void SetRemoteStubStatus(DeviceIdentify *identity, DeviceSecurityInfoCallback callback, int32_t status)
{
    if (identity == NULL || callback == NULL) {
        SECURITY_LOG_ERROR("unexpected input");
        return;
    }
    DeviceSecurityInfo *resultInfo = (DeviceSecurityInfo *)MALLOC(sizeof(DeviceSecurityInfo));
    if (resultInfo == NULL) {
        SECURITY_LOG_ERROR("no memory");
        return;
    }
    resultInfo->magicNum = SECURITY_MAGIC;
    resultInfo->result = status;
    resultInfo->level = 0;
    SECURITY_LOG_ERROR("RequestDeviceSecurityLevelSendRequest result value error");
    SECURITY_LOG_INFO("calling user callback");
    callback(identity, resultInfo);
}

static BOOL DslmPushRemoteStub(uint32_t owner, uint32_t cookie, const DeviceIdentify *identify,
    DeviceSecurityInfoCallback callback)
{
    if (GetRemoteStubList()->size > WARNING_GATE) {
        SECURITY_LOG_WARN("remote objects max warning");
    }
    uint64_t key = ((uint64_t)owner << COOKIE_SHIFT) | cookie;
    DslmRemoteStubListNode *item = (DslmRemoteStubListNode *)MALLOC(sizeof(DslmRemoteStubListNode));
    if (item == NULL) {
        SECURITY_LOG_ERROR("malloc failed, node is null");
        return false;
    }
    memset_s(item, sizeof(DslmRemoteStubListNode), 0, sizeof(DslmRemoteStubListNode));

    item->key = key;
    item->callback = callback;
    item->identify = identify;
    LockMutex(GetRemoteStubList()->mutex);
    AddListNode(&item->node, &GetRemoteStubList()->head->node);
    GetRemoteStubList()->size++;
    UnlockMutex(GetRemoteStubList()->mutex);
    return true;
}

static DslmRemoteStubListNode *DslmPopRemoteStub(uint32_t owner, uint32_t cookie)
{
    ListNode *node = NULL;
    ListNode *temp = NULL;
    DslmRemoteStubListNode *item = NULL;

    LockMutex(GetRemoteStubList()->mutex);
    uint64_t key = ((uint64_t)owner << COOKIE_SHIFT) | cookie;
    FOREACH_LIST_NODE_SAFE (node, &GetRemoteStubList()->head->node, temp) {
        item = LIST_ENTRY(node, DslmRemoteStubListNode, node);
        if (item->key == key) {
            SECURITY_LOG_INFO("pop remote stub");
            RemoveListNode(node);
            if (GetRemoteStubList()->size > 0) {
                GetRemoteStubList()->size--;
            } else {
                SECURITY_LOG_ERROR("list size is abnormal, size = %u", GetRemoteStubList()->size);
            }
            break;
        }
    }
    UnlockMutex(GetRemoteStubList()->mutex);
    return item;
}

static void ProcessCallback(uint32_t owner, uint32_t cookie, uint32_t result, const DslmCallbackInfo *info)
{
    if ((cookie == 0) || (info == NULL)) {
        return;
    }

    DslmRemoteStubListNode *item = DslmPopRemoteStub(owner, cookie);
    if (item == NULL || item->callback == NULL) {
        SECURITY_LOG_ERROR("malformed item");
        return;
    }

    DeviceSecurityInfo *resultInfo = (DeviceSecurityInfo *)MALLOC(sizeof(DeviceSecurityInfo));
    if (resultInfo == NULL) {
        SECURITY_LOG_ERROR("no memory");
        return;
    }
    resultInfo->magicNum = SECURITY_MAGIC;
    resultInfo->result = result;
    resultInfo->level = info->level;
    SECURITY_LOG_INFO("calling user callback");
    item->callback(item->identify, resultInfo);
    FREE(item);
    SECURITY_LOG_INFO("process callback succ");
}

int32_t DslmProcessGetDeviceSecurityLevel(IUnknown *iUnknown, DslmAsyncCallParams *req,
    DeviceSecurityInfoCallback callback)
{
    if (req == NULL || callback == NULL) {
        SECURITY_LOG_ERROR("invalid input");
        return ERR_INVALID_PARA;
    }

    uint64_t owner = SINGLE_OWNER;
    DslmPushRemoteStub(owner, req->cookie, req->identity, callback);
    int32_t ret = OnRequestDeviceSecLevelInfo(req->identity, req->option, owner, req->cookie, ProcessCallback);
    if (ret != SUCCESS) {
        SECURITY_LOG_ERROR("OnRequestDeviceSecLevelInfo failed, ret = %d", ret);
        SetRemoteStubStatus(req->identity, callback, ret);
        DslmRemoteStubListNode *item = DslmPopRemoteStub(owner, req->cookie);
        if (item != NULL) {
            FREE(item);
        }
        return ret;
    }
    return SUCCESS;
}