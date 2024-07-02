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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Hex;
import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.fido2.model.attestation.AttestationErrorResponseType;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CertificateService;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.mds.AttestationCertificateService;
import org.gluu.fido2.service.processors.AttestationFormatProcessor;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CertificateVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Attestation processor for attestations of fmt = packed
 *
 */
@ApplicationScoped
public class PackedAttestationProcessor implements AttestationFormatProcessor {

    @Inject
    private Logger log;

    @Inject
    private CommonVerifiers commonVerifiers;

    @Inject
    private AuthenticatorDataVerifier authenticatorDataVerifier;

    @Inject
    private CertificateVerifier certificateVerifier;

    @Inject
    private CoseService coseService;

    @Inject
    private Base64Service base64Service;

    @Inject
    private AttestationCertificateService attestationCertificateService;

    @Inject
    private CertificateService certificateService;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.packed;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, Fido2RegistrationData registration, byte[] clientDataHash,
            CredAndCounterData credIdAndCounters) {
        int alg = commonVerifiers.verifyAlgorithm(attStmt.get("alg"), authData.getKeyType());
        String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));

        if (attStmt.hasNonNull("x5c")) {
            if (appConfiguration.getFido2Configuration().isSkipValidateMdsInAttestationEnabled()) {
                log.warn("SkipValidateMdsInAttestation is enabled");
            } else {
                List<X509Certificate> attestationCertificates = getAttestationCertificates(attStmt);
                X509TrustManager tm = attestationCertificateService.populateTrustManager(authData, attestationCertificates);
                if ((tm == null) || (tm.getAcceptedIssuers().length == 0)) {
                    throw errorResponseFactory.badRequestException(AttestationErrorResponseType.PACKED_ERROR, "Packed full attestation but no certificates in metadata for authenticator " + Hex.encodeHexString(authData.getAaguid()));
                }
                X509Certificate verifiedCert = certificateVerifier.verifyAttestationCertificates(attestationCertificates, Arrays.asList(tm.getAcceptedIssuers()));
                authenticatorDataVerifier.verifyPackedAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, verifiedCert, alg);
                if (certificateVerifier.isSelfSigned(verifiedCert)) {
                    throw errorResponseFactory.badRequestException(AttestationErrorResponseType.PACKED_ERROR, "Self signed certificate");
                }
            }
            credIdAndCounters.setSignatureAlgorithm(alg);

        } else if (attStmt.hasNonNull("ecdaaKeyId")) {
            String ecdaaKeyId = attStmt.get("ecdaaKeyId").asText();
            throw errorResponseFactory.badRequestException(AttestationErrorResponseType.PACKED_ERROR, ecdaaKeyId + " is not supported");
        } else {
            PublicKey publicKey = coseService.getPublicKeyFromUncompressedECPoint(authData.getCosePublicKey());
            authenticatorDataVerifier.verifyPackedSurrogateAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, signature, publicKey, alg);
        }
        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());
        credIdAndCounters.setCredId(base64Service.urlEncodeToString(authData.getCredId()));
        credIdAndCounters.setUncompressedEcPoint(base64Service.urlEncodeToString(authData.getCosePublicKey()));
    }

	private List<X509Certificate> getAttestationCertificates(JsonNode attStmt) {
		Iterator<JsonNode> i = attStmt.get("x5c").elements();
		ArrayList<String> certificatePath = new ArrayList<>();
		while (i.hasNext()) {
		    certificatePath.add(i.next().asText());
		}
		return certificateService.getCertificates(certificatePath);
	}
}
