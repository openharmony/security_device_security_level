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

#include "dslm_bigdata.h"

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((weak)) void ReportAppInvokeEvent(const AppInvokeEvent *event)
{
    return;
}

__attribute__((weak)) void ReportSecurityInfoSyncEvent(const SecurityInfoSyncEvent *event)
{
    return;
}

#ifdef __cplusplus
}
#endif