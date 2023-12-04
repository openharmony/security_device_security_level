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
#include "dslm_service.h"

#include "ohos_init.h"
#include "ohos_types.h"
#include "utils_log.h"

static const char *FEATURE_GetName(Feature *feature);
static void FEATURE_OnInitialize(Feature *feature, Service *parent, Identity identity);
static void FEATURE_OnStop(Feature *feature, Identity identity);
static BOOL FEATURE_OnMessage(Feature *feature, Request *request);

static DslmFeature g_dslmFeature = {
    .GetName = FEATURE_GetName,
    .OnInitialize = FEATURE_OnInitialize,
    .OnStop = FEATURE_OnStop,
    .OnMessage = FEATURE_OnMessage,
    DEFAULT_IUNKNOWN_ENTRY_BEGIN,
        .DslmGetDeviceSecurityLevel = DslmProcessGetDeviceSecurityLevel,
    DEFAULT_IUNKNOWN_ENTRY_END,
    .identity = {-1, -1, NULL},
};

static const char *FEATURE_GetName(Feature *feature)
{
    return DSLM_SAMGR_FEATURE;
}

static void FEATURE_OnInitialize(Feature *feature, Service *parent, Identity identity)
{
    DslmFeature *dslmFeature = (DslmFeature *)feature;
    dslmFeature->identity = identity;
    dslmFeature->parent = parent;
}

static void FEATURE_OnStop(Feature *feature, Identity identity)
{
    g_dslmFeature.identity.queueId = NULL;
    g_dslmFeature.identity.featureId = -1;
    g_dslmFeature.identity.serviceId = -1;
}

static BOOL FEATURE_OnMessage(Feature *feature, Request *request)
{
    (void)feature;
    Response response = {.data = "Default response", .len = 0};
    SAMGR_SendResponse(request, &response);
    return TRUE;
}

static void Init(void)
{
    BOOL isRegistered = SAMGR_GetInstance()->RegisterFeature(DSLM_SAMGR_SERVICE, (Feature *)&g_dslmFeature);
    if (!isRegistered) {
        SECURITY_LOG_ERROR("[RegisterFeature S:%s F:%s] init feature failed!",
            DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
        return;
    }

    isRegistered = SAMGR_GetInstance()->RegisterFeatureApi(DSLM_SAMGR_SERVICE,
        DSLM_SAMGR_FEATURE, GET_IUNKNOWN(g_dslmFeature));
    if (!isRegistered) {
        SECURITY_LOG_ERROR("[RegisterFeatureApi S:%s F:%s] init feature failed!",
            DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
        return;
    }

    SECURITY_LOG_INFO("[RegisterFeature S:%s F:%s] init feature success!",
        DSLM_SAMGR_SERVICE, DSLM_SAMGR_FEATURE);
}
SYS_FEATURE_INIT(Init);