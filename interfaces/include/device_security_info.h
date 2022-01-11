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

#ifndef DEVICE_SECURITY_INFO_H
#define DEVICE_SECURITY_INFO_H

#include <stdint.h>

#include "device_security_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_OPTION NULL

typedef struct DeviceSecurityInfo DeviceSecurityInfo;

/**
 * 设备安全等级等级信息的回调
 */
typedef void DeviceSecurityInfoCallback(const DeviceIdentify *identify, struct DeviceSecurityInfo *info);

/**
 * 同步请求获取本机/邻居设备的设备安全
 *
 * @param [in]identify 设备标识符
 * @param [in]option option值
 * @param [out]info, 需要调用者释放
 * @return
 */
int32_t RequestDeviceSecurityInfo(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfo **info);

/**
 * 异步请求获取本机/邻居设备的设备安全
 *
 * @param [in]identify 设备标识符
 * @param [in]option option值
 * @param [in]callback
 * @return
 */
int32_t RequestDeviceSecurityInfoAsync(const DeviceIdentify *identify, const RequestOption *option,
    DeviceSecurityInfoCallback callback);

/**
 * 释放设备安全等级信息
 * @param info RequestDeviceSecLevelInfo函数返回的设备安全等级信息
 */
void FreeDeviceSecurityInfo(DeviceSecurityInfo *info);

/**
 * 提取DeviceSecLevelInfo中的设备安全等级
 * @param info [in]设备安全等级信息
 * @param level [out]设备安全等级。
 * @return
 */
int32_t GetDeviceSecurityLevelValue(const DeviceSecurityInfo *info, int32_t *level);

#ifdef __cplusplus
}
#endif

#endif // DEVICE_SECURITY_INFO_H
