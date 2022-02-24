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

#include "dslm_hidumper.h"

#include <stdlib.h>

#include "securec.h"

#include "dslm_device_list.h"
#include "dslm_messenger_wrapper.h"

static void PrintBanner(int fd)
{
    dprintf(fd, "  ___  ___ _    __  __   ___  _   _ __  __ ___ ___ ___ \n");
    dprintf(fd, " |   \\/ __| |  |  \\/  | |   \\| | | |  \\/  | _ \\ __| _ \\\n");
    dprintf(fd, " | |) \\__ \\ |__| |\\/| | | |) | |_| | |\\/| |  _/ __|   /\n");
    dprintf(fd, " |___/|___/____|_|  |_| |___/ \\___/|_|  |_|_| |___|_|_\\\n");
}

static void PrintHeader(int fd)
{
    const DeviceIdentify *device = GetSelfDevice(NULL);
    char deviceName[DEVICE_ID_MAX_LEN + 1] = {0};
    errno_t ret = memcpy_s(deviceName, DEVICE_ID_MAX_LEN + 1, device->identity, DEVICE_ID_MAX_LEN);
    if (ret != EOK) {
        return;
    }
    dprintf(fd, "selfUdid: %s\n", deviceName);
}

static void DeviceDumper(const DslmDeviceInfo *info, int32_t fd)
{
    if (info == NULL) {
        return;
    }
    char deviceName[DEVICE_ID_MAX_LEN + 1] = {0};
    errno_t ret = memcpy_s(deviceName, DEVICE_ID_MAX_LEN + 1, info->identity.identity, DEVICE_ID_MAX_LEN);
    if (ret == EOK) {
        dprintf(fd, "deviceId: %s\n", deviceName);
        dprintf(fd, "credLevel: %d\n", info->credInfo.credLevel);
        dprintf(fd, "manufacture: %s\n", info->credInfo.manufacture);
        dprintf(fd, "brand: %s\n", info->credInfo.brand);
        dprintf(fd, "\n");
    }
}

void DslmDumper(int fd)
{
    PrintBanner(fd);
    PrintHeader(fd);
    ForEachDeviceDump(DeviceDumper, fd);
}