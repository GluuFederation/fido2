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

package org.gluu.fido2.service.processor.assertion;

import java.security.PublicKey;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.fido2.ctap.AuthenticatorAttachment;
import org.gluu.fido2.exception.Fido2CompromisedDevice;
import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.service.AuthenticatorDataParser;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.processors.AssertionFormatProcessor;
import org.gluu.fido2.service.util.DigestUtilService;
import org.gluu.fido2.service.util.HexUtilService;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.fido2.service.verifier.UserVerificationVerifier;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Class which processes assertions of "tpm" fmt (attestation type)
 */
@ApplicationScoped
public class TPMAssertionFormatProcessor implements AssertionFormatProcessor {

    @Inject
    private Logger log;

    @Inject
    private CoseService coseService;

    @Inject
    private CommonVerifiers commonVerifiers;

    @Inject
    private AuthenticatorDataVerifier authenticatorDataVerifier;

    @Inject
    private UserVerificationVerifier userVerificationVerifier;

    @Inject
    private AuthenticatorDataParser authenticatorDataParser;

    @Inject
    private DataMapperService dataMapperService;

    @Inject
    private Base64Service base64Service;

    @Inject
    private DigestUtilService digestUtilService;

    @Inject
    private HexUtilService hexUtilService;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.tpm;
    }

    @Override
    public void process(String base64AuthenticatorData, String signature, String clientDataJson, Fido2RegistrationData registration,
                        Fido2AuthenticationData authenticationEntity) {
        AuthData authData = authenticatorDataParser.parseAssertionData(base64AuthenticatorData);
        commonVerifiers.verifyRpIdHash(authData, registration.getDomain());

        log.debug("User verification option {}", authenticationEntity.getUserVerificationOption());
        userVerificationVerifier.verifyUserVerificationOption(authenticationEntity.getUserVerificationOption(), authData);

        byte[] clientDataHash = digestUtilService.sha256Digest(base64Service.urlDecode(clientDataJson));

        try {
            int counter = authenticatorDataParser.parseCounter(authData.getCounters());
            commonVerifiers.verifyCounter(registration.getCounter(), counter);
            registration.setCounter(counter);

            JsonNode uncompressedECPointNode = dataMapperService.cborReadTree(base64Service.urlDecode(registration.getUncompressedECPoint()));
            PublicKey publicKey = coseService.createUncompressedPointFromCOSEPublicKey(uncompressedECPointNode);

            log.debug("Uncompressed ECPoint node {}", uncompressedECPointNode);
            log.debug("EC Public key hex {}", hexUtilService.encodeHexString(publicKey.getEncoded()));
            // apple algorithm = -7
            // windows hello algorithm is -257
            int algorithm = registration.getAttenstationRequest().contains(AuthenticatorAttachment.PLATFORM.getAttachment()) ? -257 : registration.getSignatureAlgorithm();
            log.debug("registration.getSignatureAlgorithm(): " + registration.getSignatureAlgorithm());
            log.debug("Platform authenticator: " + algorithm);
            authenticatorDataVerifier.verifyAssertionSignature(authData, clientDataHash, signature, publicKey, algorithm);

        } catch (Fido2CompromisedDevice ex) {
            throw ex;
        } catch (Exception ex) {
            throw new Fido2RuntimeException("Failed to check tpm assertion", ex);
        }
    }
}
