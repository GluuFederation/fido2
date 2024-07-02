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

package org.gluu.fido2.service.processor.attestation;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.processors.AttestationFormatProcessor;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Attestation processor for attestations of fmt = none One of the attestation
 * formats called 'none'. When you getting it, that means two things:
 * <p>
 * 1. You really don't need attestation, and so you are deliberately ignoring
 * it.
 * <p>
 * 2. You forgot to set attestation flag to 'direct' when making credential.
 * <p>
 * If you are getting attestation with fmt set to none, then no attestation
 * is provided, and you don't have anything to verify. Simply extract user
 * relevant information as specified below and save it to the database.
 */
@ApplicationScoped
public class NoneAttestationProcessor implements AttestationFormatProcessor {

    @Inject
    private Logger log;

    @Inject
    private Base64Service base64Service;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.none;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, Fido2RegistrationData credential, byte[] clientDataHash,
                        CredAndCounterData credIdAndCounters) {
        log.debug("None/Surrogate attestation {}", attStmt);

        if (!attStmt.isEmpty()) {
            log.error("Problem with None/Surrogate attestation");
            throw new Fido2RuntimeException("Problem with None/Surrogate attestation");
        }

        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());
        credIdAndCounters.setCredId(base64Service.urlEncodeToString(authData.getCredId()));
        credIdAndCounters.setUncompressedEcPoint(base64Service.urlEncodeToString(authData.getCosePublicKey()));
    }
}
