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

package org.gluu.fido2.service.verifier;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.service.processor.assertion.AssertionProcessorFactory;
import org.gluu.fido2.service.processors.AssertionFormatProcessor;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

@ApplicationScoped
public class AssertionVerifier {

    @Inject
    private Logger log;

    @Inject
    private AssertionProcessorFactory assertionProcessorFactory;

    public void verifyAuthenticatorAssertionResponse(JsonNode response, Fido2RegistrationData registration,
            Fido2AuthenticationData authenticationEntity) {
        if (!(response.hasNonNull("authenticatorData") && response.hasNonNull("clientDataJSON") && response.hasNonNull("signature"))) {
            throw new Fido2RuntimeException("Authenticator data is invalid");
        }

        String base64AuthenticatorData = response.get("authenticatorData").asText();
        String clientDataJson = response.get("clientDataJSON").asText();
        String signature = response.get("signature").asText();

        log.debug("Authenticator data {}", base64AuthenticatorData);
        AssertionFormatProcessor assertionProcessor = assertionProcessorFactory.getCommandProcessor(registration.getAttestationType());

        assertionProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);
    }

}
