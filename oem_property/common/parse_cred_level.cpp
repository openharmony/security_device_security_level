/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "parse_cred_level.h"

bool ParseDslmCredLevel(const char *text, uint32_t *out)
{
    if (text == nullptr || out == nullptr) {
        return false;
    }
    uint32_t value = 0;
    if (!OHOS::Security::Dslm::ParseCredLevel(std::string_view(text), value)) {
        return false;
    }
    *out = value;
    return true;
}
