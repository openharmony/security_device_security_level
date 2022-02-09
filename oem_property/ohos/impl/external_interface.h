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

#ifndef EXTERNAL_INTERFACE_H
#define EXTERNAL_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

struct CertChainValidateResult {
    uint8_t *udid;
    uint32_t udidLen;
    uint8_t *nounce;
    uint32_t nounceLen;
    uint8_t *cred;
    uint32_t credLen;
    uint8_t *serialNum;
    uint32_t serialNumLen;
};

int GetPkInfoListStr(bool isSelf, const uint8_t *udid, uint32_t udidLen, char **pkInfoList);
int DslmCredAttestAdapter(char *nounceStr, char *credStr, uint8_t *certChain, uint32_t *certChainLen);
int ValidateCertChainAdapter(uint8_t *data, uint32_t dataLen, struct CertChainValidateResult *resultInfo);

void FreeCertChainValidateResult(struct CertChainValidateResult *resultInfo);

#endif  // EXTERNAL_INTERFACE_H