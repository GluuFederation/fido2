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

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.commons.codec.digest.DigestUtils;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.AuthenticatorDataParser;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.processor.attestation.AttestationProcessorFactory;
import org.gluu.fido2.service.processors.AttestationFormatProcessor;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

@ApplicationScoped
public class AttestationVerifier {

    @Inject
    private Logger log;

    @Inject
    private CommonVerifiers commonVerifiers;

    @Inject
    private AuthenticatorDataParser authenticatorDataParser;

    @Inject
    private Base64Service base64Service;

    @Inject
    private DataMapperService dataMapperService;

    @Inject
    private AttestationProcessorFactory attestationProcessorFactory;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    public CredAndCounterData verifyAuthenticatorAttestationResponse(JsonNode authenticatorResponse, Fido2RegistrationData credential) {
        if (!(authenticatorResponse.hasNonNull("attestationObject") && authenticatorResponse.hasNonNull("clientDataJSON"))) {
            throw errorResponseFactory.invalidRequest("Authenticator data is invalid");
        }

        String base64AuthenticatorData = authenticatorResponse.get("attestationObject").asText();
        String clientDataJson = authenticatorResponse.get("clientDataJSON").asText();
        byte[] authenticatorDataBuffer = base64Service.urlDecode(base64AuthenticatorData);

        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        try {
            AuthData authData;
            if (authenticatorDataBuffer == null) {
                throw errorResponseFactory.invalidRequest("Attestation object is empty");
            }
            JsonNode authenticatorDataNode = dataMapperService.cborReadTree(authenticatorDataBuffer);
            if (authenticatorDataNode == null) {
                throw errorResponseFactory.invalidRequest("Attestation JSON is empty");
            }
            String fmt = commonVerifiers.verifyFmt(authenticatorDataNode, "fmt");
            log.debug("Authenticator data {} {}", fmt, authenticatorDataNode);
            
            credential.setAttestationType(fmt);
            
            JsonNode attStmt = authenticatorDataNode.get("attStmt");
            commonVerifiers.verifyAuthStatement(attStmt);

            JsonNode authDataNode = authenticatorDataNode.get("authData");
            String authDataText = commonVerifiers.verifyAuthData(authDataNode);
            authData = authenticatorDataParser.parseAttestationData(authDataText);

            int counter = authenticatorDataParser.parseCounter(authData.getCounters());
            commonVerifiers.verifyCounter(counter);
            credIdAndCounters.setCounters(counter);

            byte[] clientDataHash = DigestUtils.getSha256Digest().digest(base64Service.urlDecode(clientDataJson));
            AttestationFormatProcessor attestationProcessor = attestationProcessorFactory.getCommandProcessor(fmt);
            attestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters);

            return credIdAndCounters;
        } catch (IOException ex) {
            throw errorResponseFactory.invalidRequest("Failed to parse and verify authenticator attestation response data", ex);
        }
    }

}

