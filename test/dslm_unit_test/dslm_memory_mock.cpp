
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

#include "dslm_memory_mock.h"

#include <malloc.h>

namespace OHOS {
namespace Security {
namespace DslmUnitTest {

void *MockMalloc::Malloc(size_t size)
{
    return malloc(size);
}

void MockFree::Free(void *memory)
{
    return free(memory);
}
} // namespace DslmUnitTest
} // namespace Security
} // namespace OHOS

extern "C" {
using namespace OHOS::Security::DslmUnitTest;

// mock the UtilsMalloc, and routing to MockMalloc::Malloc
IMPLEMENT_FUNCTION_WITH_INVOKER(MockMalloc, void *, UtilsMalloc, (size_t size), MockMalloc::Malloc);

// mock the UtilsFree, and routing to MockFree::Free
IMPLEMENT_FUNCTION_WITH_INVOKER(MockFree, void, UtilsFree, (void *memory), MockFree::Free);

// mock the strcpy_s, and routing to the real strcpy_s function
IMPLEMENT_FUNCTION(MockStrcpy, errno_t, strcpy_s, (char *strDest, size_t destMax, const char *strSrc));
}