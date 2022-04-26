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

#include "dslm_bigdata.h"
#include "hisysevent.h"

#ifdef __cplusplus
extern "C" {
#endif
void ReportAppInvokeEvent(const AppInvokeEvent *event)
{
    if (event == nullptr) {
        return;
    }

    OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY,
        "start_app",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "USER_ID", event->uid,
        "COST_TIME", event->costTime,
        "RET_CODE", event->retCode,
        "SEC_LEVEL", event->secLevel,
        "RET_MODE", event->retMode,
        "LOCAL_MODEL", event->localModel,
        "TARGET_MODEL", event->targetModel,
        "PKG_NAME", event->pkgName);
}

void ReportSecurityInfoSyncEvent(const SecurityInfoSyncEvent *event)
{
    if (event == nullptr) {
        return;
    }

    OHOS::HiviewDFX::HiSysEvent::Write(
        OHOS::HiviewDFX::HiSysEvent::Domain::SECURITY,
        "start_app",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "LOCAL_MODEL", event->localModel,
        "TARGET_MODEL", event->targetModel,
        "LOCAL_VERSION", event->localVersion,
        "TARGET_VERSION", event->targetVersion,
        "CRED_TYPE", event->credType,
        "RET_CODE", event->retCode,
        "COST_TIME", event->costTime,
        "SEC_LEVEL", event->secLevel);
}

#ifdef __cplusplus
}
#endif
