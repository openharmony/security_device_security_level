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

#include "utils_mem.h"

#include <malloc.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
#define MAX_MALLOC_SIZE (64 * 1024)

void *UtilsMalloc(size_t size)
{
    if (size > MAX_MALLOC_SIZE) {
        return NULL;
    }

    return malloc(size);
}

void UtilsFree(void *memory)
{
    return free(memory);
}

#ifdef __cplusplus
}
#endif