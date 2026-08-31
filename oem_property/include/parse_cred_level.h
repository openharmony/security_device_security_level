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

#ifndef DSLM_PARSE_CRED_LEVEL_H
#define DSLM_PARSE_CRED_LEVEL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
bool ParseDslmCredLevel(const char *text, uint32_t *out);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <charconv>
#include <string_view>
#include <system_error>

namespace OHOS {
namespace Security {
namespace Dslm {
inline bool ParseCredLevel(std::string_view text, uint32_t &out)
{
    constexpr std::string_view kPrefix = "SL";
    if (text.size() <= kPrefix.size() || text.substr(0, kPrefix.size()) != kPrefix) {
        return false;
    }
    auto digits = text.substr(kPrefix.size());
    uint32_t value = 0;
    auto result = std::from_chars(digits.data(), digits.data() + digits.size(), value, 10);
    if (result.ec != std::errc() || result.ptr != digits.data() + digits.size()) {
        return false;
    }
    out = value;
    return true;
}
} // namespace Dslm
} // namespace Security
} // namespace OHOS
#endif

#endif
