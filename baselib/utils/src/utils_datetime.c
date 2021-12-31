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

#include "utils_datetime.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SEC_TO_NANOSEC 1000000000
#define SEC_TO_MICROSEC 1000000
#define SEC_TO_MILLISEC 1000
#define MILLISEC_TO_NANOSEC 1000000
#define MILLISEC_TO_USEC 1000
#define MICROSEC_TO_NANOSEC 1000

uint64_t GetMillisecondSinceBoot()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * SEC_TO_MILLISEC + ts.tv_nsec / MILLISEC_TO_NANOSEC);
}

uint64_t GetMillisecondSince1970()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * SEC_TO_MILLISEC + ts.tv_nsec / MILLISEC_TO_NANOSEC;
}

bool GetDateTimeByMillisecondSince1970(uint64_t input, DateTime *datetime)
{
    if (datetime == NULL) {
        return false;
    }
    struct tm tm;
    time_t time = (time_t)(input / SEC_TO_MILLISEC);
    localtime_r(&time, &tm);

    datetime->year = tm.tm_year + 1900; // need add 1900
    datetime->mon = tm.tm_mon + 1;
    datetime->day = tm.tm_mday;
    datetime->hour = tm.tm_hour;
    datetime->min = tm.tm_min;
    datetime->sec = tm.tm_sec;
    datetime->msec = input % SEC_TO_MILLISEC;
    return true;
}
bool GetDateTimeByMillisecondSinceBoot(uint64_t input, DateTime *datetime)
{
    if (datetime == NULL) {
        return false;
    }
    static uint64_t compensate = 0;
    if (compensate == 0) {
        compensate = GetMillisecondSince1970() - GetMillisecondSinceBoot();
    }

    return GetDateTimeByMillisecondSince1970(input + compensate, datetime);
}
#ifdef __cplusplus
}
#endif