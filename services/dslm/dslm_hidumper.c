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

#include <stdio.h>
#include <stdlib.h>

#include "dslm_device_list.h"
#include "dslm_hidumper.h"

#define SPLIT_LINE "------------------------------------------------------"
#define END_LINE "\n"

static void PrintBanner(int fd)
{
    dprintf(fd, " ___  ___ _    __  __   ___  _   _ __  __ ___ ___ ___ " END_LINE);
    dprintf(fd, "|   \\/ __| |  |  \\/  | |   \\| | | |  \\/  | _ \\ __| _ \\" END_LINE);
    dprintf(fd, "| |) \\__ \\ |__| |\\/| | | |) | |_| | |\\/| |  _/ __|   /" END_LINE);
    dprintf(fd, "|___/|___/____|_|  |_| |___/ \\___/|_|  |_|_| |___|_|_\\" END_LINE);
}

static void DumpOneDevice(const DslmDeviceInfo *info, int32_t fd)
{
    if (info == NULL) {
        return;
    }
    dprintf(fd, SPLIT_LINE END_LINE);
    dprintf(fd, "DEVICE_ID                 : %x" END_LINE, info->machine.machineId);
    dprintf(fd, "DEVICE_TYPE               : %d" END_LINE, info->deviceType);
    dprintf(fd, "DEVICE_ONLINE_STATUS      : %s" END_LINE, info->onlineStatus ? "online" : "offline");
    dprintf(fd, "DEVICE_MACHINE_STATUS     : %d" END_LINE, info->machine.currState);
    dprintf(fd, "DEVICE_VERIFIED_LEVEL     : %d" END_LINE, info->credInfo.credLevel);
    dprintf(fd, "DEVICE_VERIFIED_RESULT    : %d" END_LINE, info->result);
    dprintf(fd, "CRED_TYPE                 : %d" END_LINE, info->credInfo.credType);
    dprintf(fd, "CRED_SIGNTIME             : %s" END_LINE, info->credInfo.signTime);
    dprintf(fd, "CRED_MANUFACTURE          : %s" END_LINE, info->credInfo.manufacture);
    dprintf(fd, "CRED_BAND                 : %s" END_LINE, info->credInfo.brand);
    dprintf(fd, "CRED_MODEL                : %s" END_LINE, info->credInfo.model);
    dprintf(fd, "CRED_SOFTWARE_VERSION     : %s" END_LINE, info->credInfo.softwareVersion);
    dprintf(fd, "CRED_SECURITY_LEVEL       : %s" END_LINE, info->credInfo.securityLevel);
    dprintf(fd, "CRED_VERSION              : %s" END_LINE, info->credInfo.version);
    dprintf(fd, SPLIT_LINE END_LINE);
}

static void PrintAllDevices(int fd)
{
    ForEachDeviceDump(DumpOneDevice, fd);
}

void DslmDumper(int fd)
{
    PrintBanner(fd);
    PrintAllDevices(fd);
}