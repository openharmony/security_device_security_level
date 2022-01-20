/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "dslm_device_list.h"

#include <securec.h>
#include <stdbool.h>

#include "utils_datetime.h"
#include "utils_list.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_mutex.h"

#include "device_security_defines.h"
#include "dslm_core_defines.h"
#include "dslm_fsm_process.h"

#define MAX_DEVICE_CNT 128

static inline Mutex *GetDeviceListMutex()
{
    static Mutex mutex = INITED_MUTEX;
    return &mutex;
}

static ListHead *GetDeviceList()
{
    static ListHead list = INIT_LIST(list);
    return &list;
}

static int32_t GetDeviceListSize()
{
    int32_t size = 0;
    ListNode *node = NULL;

    LockMutex(GetDeviceListMutex());
    FOREACH_LIST_NODE (node, GetDeviceList()) {
        size++;
    }
    UnlockMutex(GetDeviceListMutex());
    return size;
}

DslmDeviceInfo *GetDslmDeviceInfo(const DeviceIdentify *device)
{
    if (device == NULL) {
        return NULL;
    }

    DslmDeviceInfo *result = NULL;
    ListNode *node = NULL;

    LockMutex(GetDeviceListMutex());
    FOREACH_LIST_NODE (node, GetDeviceList()) {
        DslmDeviceInfo *info = LIST_ENTRY(node, DslmDeviceInfo, linkNode);
        if (IsSameDevice(&info->identity, device)) {
            result = info;
            break;
        }
    }
    UnlockMutex(GetDeviceListMutex());
    return result;
}

DslmDeviceInfo *CreatOrGetDslmDeviceInfo(const DeviceIdentify *device)
{
    if (device == NULL) {
        return NULL;
    }

    if (device->length != DEVICE_ID_MAX_LEN) {
        return NULL;
    }

    DslmDeviceInfo *info = GetDslmDeviceInfo(device);
    if (info != NULL) {
        return info;
    }

    if (GetDeviceListSize() > MAX_DEVICE_CNT) {
        return NULL;
    }

    info = MALLOC(sizeof(DslmDeviceInfo));
    if (info == NULL) {
        return NULL;
    }
    memset_s(info, sizeof(DslmDeviceInfo), 0, sizeof(DslmDeviceInfo));

    if (memcpy_s(&info->identity, sizeof(DeviceIdentify), device, sizeof(DeviceIdentify)) != EOK) {
        FREE(info);
        return NULL;
    }
    InitDslmStateMachine(info);
    LockMutex(GetDeviceListMutex());
    AddListNode(&info->linkNode, GetDeviceList());
    InitListHead(&info->notifyList);
    UnlockMutex(GetDeviceListMutex());
    SECURITY_LOG_INFO("Create new DslmDeviceInfo %{public}x", info->machine.machineId);
    return info;
}

bool IsSameDevice(const DeviceIdentify *first, const DeviceIdentify *second)
{
    if ((first == NULL) || (second == NULL)) {
        return false;
    }
    if (first->length != second->length) {
        return false;
    }
    if (memcmp(first->identity, second->identity, first->length) != 0) {
        return false;
    }
    return true;
}

void ForEachDeviceDump(const ProcessDumpFunction dumper, int32_t dumpHandle)
{
    ListNode *node = NULL;
    if (dumper == NULL) {
        return;
    }

    LockMutex(GetDeviceListMutex());
    FOREACH_LIST_NODE (node, GetDeviceList()) {
        const DslmDeviceInfo *info = LIST_ENTRY(node, DslmDeviceInfo, linkNode);
        dumper(info, dumpHandle);
    }
    UnlockMutex(GetDeviceListMutex());
}
