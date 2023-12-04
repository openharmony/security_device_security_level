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

#ifndef SEC_UTILS_JSON_H
#define SEC_UTILS_JSON_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *DslmJsonHandle;

DslmJsonHandle DslmCreateJson(const char *data);
void DslmDestroyJson(DslmJsonHandle handle);

int32_t DslmGetJsonFieldInt(DslmJsonHandle handle, const char *field);
uint32_t DslmGetJsonFieldIntArray(DslmJsonHandle handle, const char *field, int32_t *array, int32_t arrayLen);
const char *DslmGetJsonFieldString(DslmJsonHandle handle, const char *field);
DslmJsonHandle DslmGetJsonFieldJson(DslmJsonHandle handle, const char *field);

DslmJsonHandle DslmGetJsonFieldJsonArray(DslmJsonHandle handle, uint32_t num);
int32_t DslmGetJsonFieldJsonArraySize(DslmJsonHandle handle);

void DslmAddFieldIntToJson(DslmJsonHandle handle, const char *field, int32_t value);
void DslmAddFieldIntArrayToJson(DslmJsonHandle handle, const char *field, const int32_t *array, int32_t arrayLen);
void DslmAddFieldBoolToJson(DslmJsonHandle handle, const char *field, bool value);
void DslmAddFieldStringToJson(DslmJsonHandle handle, const char *field, const char *value);
void DslmAddFieldJsonToJson(DslmJsonHandle handle, const char *field, DslmJsonHandle json);

char *DslmConvertJsonToString(DslmJsonHandle handle);

bool DslmCompareJsonData(DslmJsonHandle handleA, DslmJsonHandle handleB, bool caseSensitive);

#ifdef __cplusplus
}
#endif

#endif // SEC_UTILS_JSON_H