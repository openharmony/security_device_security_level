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

#include "dslm_ohos_verify.h"

#include "utils_log.h"
#include <securec.h>
#include <string.h>

#include "utils_mem.h"

#define OHOS_DEFAULT_LEVEL 1
int32_t VerifyOhosDslmCred(const DeviceIdentify *device, uint64_t challenge, const DslmCredBuff *credBuff,
    DslmCredInfo *credInfo)
{
    SECURITY_LOG_INFO("Invoke VerifyOhosDslmCred = %{public}s", (char *)credBuff->credVal);
    credInfo->credLevel = OHOS_DEFAULT_LEVEL;
    return 0;
}