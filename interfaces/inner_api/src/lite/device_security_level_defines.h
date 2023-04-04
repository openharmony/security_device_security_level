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

#ifndef DEVICE_SECURITY_LEVEL_DEFINES_H
#define DEVICE_SECURITY_LEVEL_DEFINES_H

#include "device_security_defines.h"
#include "device_security_info.h"

#define DSLM_SAMGR_SERVICE "dslm_service"
#define DSLM_SAMGR_FEATURE "dslm_feature"
#define SECURITY_MAGIC 0xABCD1234

enum {
    CMD_SET_DEVICE_SECURITY_LEVEL = 1,
};

struct DeviceSecurityInfo {
    uint32_t magicNum;
    uint32_t result;
    uint32_t level;
};

#endif // DEVICE_SECURITY_LEVEL_DEFINES_H
