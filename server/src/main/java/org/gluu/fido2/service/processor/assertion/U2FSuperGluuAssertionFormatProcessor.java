package org.gluu.fido2.service.processor.assertion;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.fido2.ctap.AttestationFormat;
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
 *  Class which processes assertions of "fido2-u2f" fmt (attestation type)
 *
 */
@ApplicationScoped
public class U2FSuperGluuAssertionFormatProcessor implements AssertionFormatProcessor {

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
        return AttestationFormat.fido_u2f_super_gluu;
    }

    @Override
    public void process(String base64AuthenticatorData, String signature, String clientDataJson, Fido2RegistrationData registration,
            Fido2AuthenticationData authenticationEntity) {
        AuthData authData = authenticatorDataParser.parseAssertionData(base64AuthenticatorData);

//        String clientDataRaw = commonVerifiers.verifyClientRaw(response).asText();
        userVerificationVerifier.verifyUserPresent(authData);

        String clientDataJsonString = new String(base64Service.urlDecode(clientDataJson), StandardCharsets.UTF_8);
        clientDataJsonString = clientDataJsonString.replace("\"type\"", "\"typ\"");
        byte[] clientDataHash = digestUtilService.sha256Digest(clientDataJsonString.getBytes(StandardCharsets.UTF_8));

        try {
            int counter = authenticatorDataParser.parseCounter(authData.getCounters());
            commonVerifiers.verifyCounter(registration.getCounter(), counter);
            registration.setCounter(counter);

            JsonNode uncompressedECPointNode = dataMapperService.cborReadTree(base64Service.urlDecode(registration.getUncompressedECPoint()));
            PublicKey publicKey = coseService.createUncompressedPointFromCOSEPublicKey(uncompressedECPointNode);
            log.debug("Uncompressed ECpoint node {}", uncompressedECPointNode);
            log.debug("Public key hex {}", hexUtilService.encodeHexString(publicKey.getEncoded()));

            authenticatorDataVerifier.verifyAssertionSignature(authData, clientDataHash, signature, publicKey, registration.getSignatureAlgorithm());
        } catch (Exception ex) {
            throw new Fido2RuntimeException("Failed to check U2F SuperGluu assertion", ex);
        }
    }
}
