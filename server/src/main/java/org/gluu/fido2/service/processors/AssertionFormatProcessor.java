/*
 * Copyright (c) 2018 Mastercard
 * Copyright (c) 2020 Gluu
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */

package org.gluu.fido2.service.processors;

import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2RegistrationData;

/**
 * Interface class for AssertionFormatProcessor
 *
 */
public interface AssertionFormatProcessor {

    AttestationFormat getAttestationFormat();

    void process(String base64AuthenticatorData, String signature, String clientDataJson, Fido2RegistrationData registration,
            Fido2AuthenticationData authenticationEntity);
}
