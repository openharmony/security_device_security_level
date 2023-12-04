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

#include "dslm_service.h"
#include "ohos_init.h"
#include "ohos_types.h"
#include "utils_log.h"

#include "device_security_defines.h"
#include "dslm_rpc_process.h"

static const char *GetName(Service *service);
static BOOL Initialize(Service *service, Identity identity);
static BOOL MessageHandle(Service *service, Request *msg);
static TaskConfig GetTaskConfig(Service *service);

static DslmService g_dslmService = {
    .GetName = GetName,
    .Initialize = Initialize,
    .MessageHandle = MessageHandle,
    .GetTaskConfig = GetTaskConfig,
    .identity = {-1, -1, NULL},
};

static const char *GetName(Service *service)
{
    return DSLM_SAMGR_SERVICE;
}

static BOOL Initialize(Service *service, Identity identity)
{
    DslmService *dslmService = (DslmService *)service;
    dslmService->identity = identity;
    if (InitService() != SUCCESS) {
        SECURITY_LOG_ERROR("init service failed");
        return FALSE;
    }
    SECURITY_LOG_INFO("[Initialize S:%s]: init service success", DSLM_SAMGR_SERVICE);
    return TRUE;
}

static BOOL MessageHandle(Service *service, Request *msg)
{
    (void)service;
    return TRUE;
}
static TaskConfig GetTaskConfig(Service *service)
{
#ifdef L0_MINI
    TaskConfig config = {LEVEL_HIGH, PRI_BELOW_NORMAL, 0xffff, 20, SINGLE_TASK};
#else
    TaskConfig config = {LEVEL_HIGH, PRI_BELOW_NORMAL, 0x800, 20, SHARED_TASK};
#endif
    return config;
}

static void Init(void)
{
    BOOL isRegistered = SAMGR_GetInstance()->RegisterService((Service *)&g_dslmService);
    if (!isRegistered) {
        SECURITY_LOG_ERROR("[RegisterService S:%s] init service failed!", DSLM_SAMGR_SERVICE);
        return;
    }

    SECURITY_LOG_INFO("[RegisterService S:%s] init service success!", DSLM_SAMGR_SERVICE);
}
SYS_SERVICE_INIT(Init);