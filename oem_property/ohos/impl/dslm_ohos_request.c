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

#include "dslm_ohos_request.h"

#include "utils_log.h"
#include <securec.h>
#include <string.h>

#include "utils_mem.h"

int32_t RequestOhosDslmCred(const DeviceIdentify *device, const RequestObject *obj, DslmCredBuff **credBuff)
{
    SECURITY_LOG_INFO("Invoke RequestOhosDslmCred");
    static const char *credStr =
        "ewogICAgInR5cCI6ICJEU0wiLAp9."
        "eyJzZWN1cml0eUxldmVsIjoiU0w0IiwibWFudWZhY3R1cmUiOiJNQU5VIiwic2lnblRpbWUiOiIyMDIxMTEwOTExMjczNCIsIm1vZGVsIjoiTU"
        "9ERU"
        "wiLCJ0eXBlIjoiZGVidWciLCJ1ZGlkIjoiMTIzNDU2Nzg5MEFCQ0RFRiIsInZlcnNpb24iOiIxLjAiLCJicmFuZCI6IkJSQU5EIiwic29mdHdh"
        "cmVW"
        "ZXJzaW9uIjoiMi4xLjAuNDIifQ==.MEUCIQCMglMcuEUhJBwbkPbgNi_VI7ksPkGZXBPMQI_YmepubQIgPuF9WLjaTum9d_"
        "KhqmVdjfRmcFbhPh4Laq2NnlVz3uc."
        "W3sidXNlclB1YmxpY0tleSI6Ik1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWFnOFZIMzN4OUpDOTYwSWsxejNKNmo1cnk0OV"
        "JENG"
        "t0TTBvQUZGenhiNHdOdS1OckZSbm5XbnZmR3hGTW16VFBMLWYxY1NqWGd2UV9NdU9aenVpclNnIiwiYWxnb3JpdGhtIjoiU0hBMzg0d2l0aEVD"
        "RFNB"
        "Iiwic2lnbmF0dXJlIjoiTUdVQ01DakdwWEZPNlRjb2NtWFdMdHU1SXQ0LVRJNzFoNzhLdDYyYjZ6Mm9tcnNVWElHcnFsMTZXT0ExV2ZfdDdGSU"
        "1RZ0"
        "l4QVBHMlV5T2d0dk1pbi1hbVR6Wi1DN2ZyMWttVl9jODc4ckFnZVlrUGFxWWdPWWpiSGN0QnFzMkJCV05LMGsxTnJRIn0seyJ1c2VyUHVibGlj"
        "S2V5"
        "IjoiTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVvM0N1Q0VMQzdTaUxhSkNCQ0RkY0NwZXRnSUdraFpMc0ZfYTBkZFUxQ1I3dzU0em"
        "ppc0"
        "NYWkdfdXk2ZGtGZWZrZTNVMW9CaWw0eGk1OU5xeVpOZ1FQbEFISVVHeWtRcVl4cHg1WjBqQUJCSnlBSlVscHRxM0p1Wk5UQTdIOVVLNyIsImFs"
        "Z29y"
        "aXRobSI6IlNIQTM4NHdpdGhFQ0RTQSIsInNpZ25hdHVyZSI6Ik1HVUNNQ1ZXUWIxdXFLb1E5SUFMaWJiWUlUX1NWSENXem84akcwRG1WNGt6Q0"
        "JNQ3"
        "pRQU0xZEFaSERGWFdidGUyY0FfWXdJeEFJSXVmaXJHbnN3NlBEV0txRm1mQmQ5Y3BubEFyLXVXV0RqZ2xuenoyRmx2LXNkaVhYRnR3amo3Y1hU"
        "TF9F"
        "NmJRUSJ9LHsidXNlclB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFU09kcnY3eXhEaFoxWmRUdDB3QUxCMnhYc0"
        "ZsUG"
        "V2TkQ0b1lfWE44QWtFTVllWVVyTXBkX1hTQTdlTHo5eVJaa08yX3RoSEx4bUpURGZrOUJFeTlTa0xxUF9xOGZJdzBhSXNBMHI0SlN0djh4YVo0"
        "RWxV"
        "TGxPV2QxXzF4YV9fdnIiLCJhbGdvcml0aG0iOiJTSEEzODR3aXRoRUNEU0EiLCJzaWduYXR1cmUiOiJNR1FDTURmODNSNktLdm9tZnZyZVYycH"
        "hVSE"
        "pXb3RwM3BVOUdBWU5tcU1XUmVGcGp6WHpOVjc5dHNrZTBaa21JTVh3TXNBSXdXNUFiOWk4SnlObEp0WDJZcnpaYzJna3RranZ0U2JiSnYwaWhu"
        "Umdx"
        "MWNjUHBrVDJOc3F4ekJrZkRqOGhQWllzIn1d";

    DslmCredBuff *out = CreateDslmCred(CRED_TYPE_STANDARD, strlen(credStr) + 1, (uint8_t *)credStr);
    if (out == NULL) {
        return ERR_MEMORY_ERR;
    }
    *credBuff = out;
    return SUCCESS;
}
