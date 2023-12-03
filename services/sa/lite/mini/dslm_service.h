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

#ifndef DSLM_SERVICE_H
#define DSLM_SERVICE_H

#include "iunknown.h"
#include "samgr_lite.h"

#include "device_security_defines.h"
#include "device_security_level_defines.h"
#include "dslm_inner_process.h"

#define DSLM_SAMGR_SERVICE "dslm_service"
#define DSLM_SAMGR_FEATURE "dslm_feature"

typedef struct DslmService {
    INHERIT_SERVICE;
    Identity identity;
} DslmService;

typedef struct DslmFeatureApi {
    INHERIT_IUNKNOWN;
    int32_t (*DslmGetDeviceSecurityLevel)(IUnknown *iUnknown, DslmAsyncCallParams *req, DeviceSecurityInfoCallback cb);
} DslmFeatureApi;

typedef struct DslmFeature {
    INHERIT_FEATURE;
    INHERIT_IUNKNOWNENTRY(DslmFeatureApi);
    Identity identity;
    Service *parent;
} DslmFeature;

void DslmServiceInit(void);
void DslmFeatureInit(void);

#endif // DSLM_SERVICE_H