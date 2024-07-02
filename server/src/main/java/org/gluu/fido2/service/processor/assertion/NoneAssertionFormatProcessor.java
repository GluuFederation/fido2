package org.gluu.fido2.service.processor.assertion;

import java.security.PublicKey;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.fido2.exception.Fido2CompromisedDevice;
import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.service.AuthenticatorDataParser;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.processors.AssertionFormatProcessor;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.fido2.service.verifier.UserVerificationVerifier;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Class which processes assertions of "none" fmt (attestation type)
 */
@ApplicationScoped
public class NoneAssertionFormatProcessor implements AssertionFormatProcessor {

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

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.none;
    }

    @Override
    public void process(String base64AuthenticatorData, String signature, String clientDataJson, Fido2RegistrationData registration,
                        Fido2AuthenticationData authenticationEntity) {
        log.debug("Registration: {}", registration);

        AuthData authData = authenticatorDataParser.parseAssertionData(base64AuthenticatorData);
        commonVerifiers.verifyRpIdHash(authData, registration.getDomain());

        log.debug("User verification option: {}", authenticationEntity.getUserVerificationOption());
        userVerificationVerifier.verifyUserVerificationOption(authenticationEntity.getUserVerificationOption(), authData);

        byte[] clientDataHash = DigestUtils.getSha256Digest().digest(base64Service.urlDecode(clientDataJson));

        try {
            int counter = authenticatorDataParser.parseCounter(authData.getCounters());
            commonVerifiers.verifyCounter(registration.getCounter(), counter);
            registration.setCounter(counter);

            JsonNode uncompressedECPointNode = dataMapperService.cborReadTree(base64Service.urlDecode(registration.getUncompressedECPoint()));
            PublicKey publicKey = coseService.createUncompressedPointFromCOSEPublicKey(uncompressedECPointNode);

            log.debug("Uncompressed ECpoint node: {}", uncompressedECPointNode);
            log.debug("EC Public key hex: {}", Hex.encodeHexString(publicKey.getEncoded()));
            log.debug("Registration algorithm: {}, default use: -7", registration.getSignatureAlgorithm());
            authenticatorDataVerifier.verifyAssertionSignature(authData, clientDataHash, signature, publicKey, -7);

        } catch (Fido2CompromisedDevice ex) {
            log.error("Error compromised device: {}", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            log.error("Error to check none assertion: {}", ex.getMessage());
            throw new Fido2RuntimeException("Failed to check none assertion: {}", ex.getMessage(), ex);
        }
    }
}
