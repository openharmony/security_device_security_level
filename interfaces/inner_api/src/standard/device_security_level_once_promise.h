/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DEVICE_SECURITY_LEVEL_ONCE_PROMISE
#define DEVICE_SECURITY_LEVEL_ONCE_PROMISE

#include <atomic>
#include <future>
#include "hilog/log_cpp.h"

namespace OHOS {
namespace Security {
namespace DeviceSecurityLevel {
template <typename T>
class OncePromise {
public:
    OncePromise() = default;
    void SetValue(T value)
    {
        std::lock_guard<std::mutex> lock(promiseMutex_);
        if (isSetValue_) {
            HILOG_ERROR(LOG_CORE, "set value again");
            return;
        }
        isSetValue_ = true;
        HILOG_INFO(LOG_CORE, "set value success");
        promise_.set_value(value);
    }
    std::future<T> GetFuture()
    {
        std::lock_guard<std::mutex> lock(promiseMutex_);
        return promise_.get_future();
    }
private:
    std::atomic<bool> isSetValue_{false};
    std::promise<T> promise_;
    std::mutex promiseMutex_;
};

} // namespace DeviceSecurityLevel
} // namespace Security
} // namespace OHOS

#endif // DEVICE_SECURITY_LEVEL_ONCE_PROMISE