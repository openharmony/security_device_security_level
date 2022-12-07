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

#ifndef DSLM_MALLOC_MOCK_H
#define DSLM_MALLOC_MOCK_H

#include "securec.h"

#include "c_mocker.h"

namespace OHOS {
namespace Security {
namespace DslmUnitTest {
class MockMalloc : public OHOS::Security::UnitTest::CMocker<MockMalloc> {
public:
    DECLARE_METHOD(void *, UtilsMalloc, (size_t size));

    static void *Malloc(size_t size);
};

class MockFree : public OHOS::Security::UnitTest::CMocker<MockFree> {
public:
    DECLARE_METHOD(void, UtilsFree, (void *memory));

    static void Free(void *memory);
};

class MockStrcpy : public OHOS::Security::UnitTest::CMocker<MockStrcpy> {
public:
    DECLARE_METHOD(errno_t, strcpy_s, (char *strDest, size_t destMax, const char *strSrc));
};

} // namespace DslmUnitTest
} // namespace Security
} // namespace OHOS

#endif // DSLM_MSG_INTERFACE_MOCK_H