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

#include <pthread.h>
#include <securec.h>

#include "device_security_level_defines.h"
#include "device_security_level_proxy.h"

#include "ohos_types.h"
#include "utils_log.h"
#include "utils_mem.h"
#include "utils_mutex.h"

#define MAX_IPC_DATA_LEN 0x100

static inline Mutex *GetMutex(void)
{
    static Mutex mutex = INITED_MUTEX;
    return &mutex;
}

static int DslmIpcCallback(IOwner owner, int code, IpcIo *reply)
{
    uint32_t result = ERR_DEFAULT;
    uint32_t level = 0;

    if (owner == NULL) {
        return ERR_INVALID_PARA;
    }

    struct DslmCallbackHolder *holder = (struct DslmCallbackHolder *)owner;

    ReadUint32(reply, &result);
    if (result == SUCCESS) {
        ReadUint32(reply, &level);
        SECURITY_LOG_INFO("[TID:0x%lx] Notify Remote result: %u, level: %u", pthread_self(), result, level);
    } else {
        level = 0;
        SECURITY_LOG_ERROR("RequestDeviceSecurityLevelSendRequest result value error, ret is %d", result);
    }

    if (holder->callback != NULL) {
        DeviceSecurityInfo *info = (DeviceSecurityInfo *)MALLOC(sizeof(DeviceSecurityInfo));
        if (info == NULL) {
            return ERR_NO_MEMORY;
        }
        info->magicNum = SECURITY_MAGIC;
        info->result = result;
        info->level = level;
        SECURITY_LOG_INFO("calling user callback");
        holder->callback(&holder->identity, info);
    }

    return SUCCESS;
}

static BOOL DslmIpcAsyncCallImpl(IUnknown *iUnknown, const DeviceIdentify identify, const RequestOption option,
    uint32_t cookie, const DeviceSecurityInfoCallback callback)
{
    if (identify.length == 0 || identify.length > DEVICE_ID_MAX_LEN) {
        SECURITY_LOG_ERROR("RequestDeviceSecurityLevel invalid para len.");
        return ERR_INVALID_PARA;
    }
    struct DslmCallbackHolder owner = {identify, callback};
    DslmClientProxy *proxy = (DslmClientProxy *)iUnknown;
    IpcIo request;
    char data[MAX_IPC_DATA_LEN];
    IpcIoInit(&request, data, MAX_IPC_DATA_LEN, 0);
    /* DeviceIdentify */
    WriteUint32(&request, identify.length);
    WriteBuffer(&request, identify.identity, DEVICE_ID_MAX_LEN);
    /* option */
    WriteUint64(&request, option.challenge);
    WriteUint32(&request, option.timeout);
    WriteUint32(&request, option.extra);
    /* cookie */
    WriteUint32(&request, cookie);

    int ret = proxy->Invoke((IClientProxy *)proxy, CMD_SET_DEVICE_SECURITY_LEVEL, &request, &owner, DslmIpcCallback);
    if (ret != EC_SUCCESS) {
        SECURITY_LOG_ERROR("RequestDeviceSecurityLevelSendRequest send failed, ret is %d", ret);
        return ret;
    }

    return SUCCESS;
}

void *DslmCreatClient(const char *service, const char *feature, uint32 size)
{
    (void)service;
    (void)feature;
    uint32_t len = size + sizeof(DslmClientEntry);
    uint8_t *client = (uint8_t *)MALLOC(len);
    if (client == NULL) {
        SECURITY_LOG_ERROR("malloc error");
        return NULL;
    }
    (void)memset_s(client, len, 0, len);
    DslmClientEntry *entry = (DslmClientEntry *)&client[size];
    entry->ver = ((uint16_t)CLIENT_PROXY_VER | (uint16_t)DEFAULT_VERSION);
    entry->ref = 1;
    entry->iUnknown.QueryInterface = IUNKNOWN_QueryInterface;
    entry->iUnknown.AddRef = IUNKNOWN_AddRef;
    entry->iUnknown.Release = IUNKNOWN_Release;
    entry->iUnknown.Invoke = NULL;
    entry->iUnknown.DslmIpcAsyncCall = DslmIpcAsyncCallImpl;
    return client;
}

void DslmDestroyClient(const char *service, const char *feature, void *proxy)
{
    (void)service;
    (void)feature;
    FREE(proxy);
}

static DslmClientProxy *GetClientProxy(void)
{
    SAMGR_RegisterFactory(DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE, DslmCreatClient, DslmDestroyClient);
    DslmClientProxy *proxy = NULL;
    SECURITY_LOG_INFO("[GetFeatureApi S:%s F:%s] begin", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
    IUnknown *iUnknown = SAMGR_GetInstance()->GetFeatureApi(DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
    if (iUnknown == NULL) {
        SECURITY_LOG_ERROR("[GetFeatureApi S:%s F:%s]: failed", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
        return NULL;
    }

    int32_t ret = iUnknown->QueryInterface(iUnknown, CLIENT_PROXY_VER, (void **)&proxy);
    if (ret != SUCCESS || proxy == NULL) {
        SECURITY_LOG_ERROR("[QueryInterface CLIENT_PROXY_VER S:%s, F:%s] failed", DSLM_SAMGR_SERVICE,
            DSLM_SAMGR_FEATURE);
        return NULL;
    }
    SECURITY_LOG_INFO("[QueryInterface CLIENT_PROXY_VER S:%s, F:%s] success", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
    return proxy;
}

static void ReleaseClientProxy(DslmClientProxy *clientProxy)
{
    if (clientProxy == NULL) {
        return;
    }

    int32 ret = clientProxy->Release((IUnknown *)clientProxy);
    SECURITY_LOG_INFO("[Release api S:%s, F:%s]: ret:%d", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE, ret);
}

int32_t RequestDeviceSecurityInfoAsyncImpl(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfoCallback callback)
{
    static uint32_t generated = 0;
    if (identify == NULL || callback == NULL) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo input error");
        return ERR_INVALID_PARA;
    }

    static RequestOption defaultOption = {0, DEFAULT_KEEP_LEN, 0};
    if (option == NULL) {
        option = &defaultOption;
    }
    if (option->timeout > MAX_KEEP_LEN) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo input error, timeout too long");
        return ERR_INVALID_PARA;
    }

    LockMutex(GetMutex());
    uint32_t cookie = ++generated;
    UnlockMutex(GetMutex());
    DslmClientProxy *proxy = GetClientProxy();
    if (proxy == NULL) {
        SECURITY_LOG_ERROR("[GetFeatureApi S:%s F:%s]: failed", DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
        return ERR_IPC_PROXY_ERR;
    }

    if (proxy->DslmIpcAsyncCall == NULL) {
        SECURITY_LOG_ERROR("proxy has NULL api");
        return ERR_IPC_PROXY_ERR;
    }
    BOOL result = proxy->DslmIpcAsyncCall((IUnknown *)proxy, *identify, *option, cookie, callback);
    if (result != SUCCESS) {
        SECURITY_LOG_ERROR("GetDeviceSecurityInfo RequestDeviceSecurityLevel error");
        return result;
    }
    SECURITY_LOG_INFO("GetDeviceSecurityInfo RequestDeviceSecurityLevel success");
    ReleaseClientProxy(proxy);
    return SUCCESS;
}