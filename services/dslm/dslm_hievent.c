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

#include "dslm_hievent.h"

#include <securec.h>

#include "dslm_bigdata.h"

void ReportHiEventInfoSync(const DslmDeviceInfo *info)
{
    if (info == NULL) {
        return;
    }
    if (!ReportSecurityInfoSyncEvent) {
        return;
    }
    SecurityInfoSyncEvent event;
    memset_s(&event, sizeof(SecurityInfoSyncEvent), 0, sizeof(SecurityInfoSyncEvent));

    if (info->lastResponseTime >= info->lastRequestTime) {
        event.costTime = info->lastResponseTime - info->lastRequestTime;
    }

    event.retCode = info->result;
    event.secLevel = info->credInfo.credLevel;
    event.localVersion = GetCurrentVersion();
    event.targetVersion = info->version;
    if (memcpy_s(event.targetModel, MODEL_MAX_LEN, info->credInfo.model, CRED_INFO_MODEL_LEN) != EOK) {
        memset_s(event.targetModel, MODEL_MAX_LEN, 0, MODEL_MAX_LEN);
    }

    event.credType = info->credInfo.credType;
    ReportSecurityInfoSyncEvent(&event);
}

void ReportHiEventAppInvoke(const DslmDeviceInfo *info)
{
    if (info == NULL) {
        return;
    }

    if (!ReportAppInvokeEvent) {
        return;
    }
    AppInvokeEvent event;
    memset_s(&event, sizeof(AppInvokeEvent), 0, sizeof(AppInvokeEvent));
    event.costTime = 0;
    if (info->lastResponseTime >= info->lastRequestTime) {
        event.costTime = info->lastResponseTime - info->lastRequestTime;
    }
    event.uid = 0;
    event.retCode = info->result;
    event.secLevel = info->credInfo.credLevel;
    event.retMode = (info->result == ERR_NEED_COMPATIBLE) ? 1 : 0;

    if (memcpy_s(event.targetModel, MODEL_MAX_LEN, info->credInfo.model, CRED_INFO_MODEL_LEN) != EOK) {
        memset_s(event.targetModel, MODEL_MAX_LEN, 0, MODEL_MAX_LEN);
    }

    ReportAppInvokeEvent(&event);
}