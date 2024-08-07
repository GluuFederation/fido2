package org.gluu.fido2.service.processor.attestation;

import java.nio.charset.Charset;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.commons.codec.digest.DigestUtils;
import org.gluu.fido2.ctap.AttestationFormat;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CertificateService;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.mds.AttestationCertificateService;
import org.gluu.fido2.service.processors.AttestationFormatProcessor;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CertificateVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.fido2.service.verifier.UserVerificationVerifier;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Attestation processor for attestations of fmt =fido-u2f
 *
 */
@ApplicationScoped
public class U2FSuperGluuAttestationProcessor implements AttestationFormatProcessor {

    @Inject
    private Logger log;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private CommonVerifiers commonVerifiers;

    @Inject
    private AuthenticatorDataVerifier authenticatorDataVerifier;

    @Inject
    private UserVerificationVerifier userVerificationVerifier;

    @Inject
    private AttestationCertificateService attestationCertificateService;

    @Inject
    private CertificateVerifier certificateVerifier;

    @Inject
    private CoseService coseService;

    @Inject
    private Base64Service base64Service;

    @Inject
    private CertificateService certificateService;

    @Override
    public AttestationFormat getAttestationFormat() {
        return AttestationFormat.fido_u2f_super_gluu;
    }

    @Override
    public void process(JsonNode attStmt, AuthData authData, Fido2RegistrationData registration, byte[] clientDataHash,
                        CredAndCounterData credIdAndCounters) {
        int alg = -7;

        String signature = commonVerifiers.verifyBase64String(attStmt.get("sig"));
        commonVerifiers.verifyAAGUIDZeroed(authData);

        userVerificationVerifier.verifyUserPresent(authData);

        if (attStmt.hasNonNull("x5c")) {
            Iterator<JsonNode> i = attStmt.get("x5c").elements();
            ArrayList<String> certificatePath = new ArrayList<String>();
            while (i.hasNext()) {
                certificatePath.add(i.next().asText());
            }
            // TODO: Regenerate Super Gluu Cert
            List<X509Certificate> certificates = certificateService.getCertificates(certificatePath, false);

            credIdAndCounters.setSignatureAlgorithm(alg);
//            List<X509Certificate> trustAnchorCertificates = attestationCertificateService.getAttestationRootCertificates((JsonNode) null, certificates);
//				Certificate verifiedCert = certificateVerifier.verifyAttestationCertificates(certificates, trustAnchorCertificates);
			Certificate verifiedCert = certificates.get(0);
            byte[] challengeHash = DigestUtils.getSha256Digest().digest(registration.getChallenge().getBytes(Charset.forName("UTF-8")));
            
            // RP ID hash is application for Super Gluu
            byte[] rpIdhash = DigestUtils.getSha256Digest().digest(registration.getApplicationId().getBytes(Charset.forName("UTF-8")));
			
            authenticatorDataVerifier.verifyU2FAttestationSignature(authData, rpIdhash, challengeHash, signature, verifiedCert, alg);
        }

        credIdAndCounters.setAttestationType(getAttestationFormat().getFmt());
        credIdAndCounters.setCredId(base64Service.urlEncodeToString(authData.getCredId()));
        credIdAndCounters.setUncompressedEcPoint(base64Service.urlEncodeToString(authData.getCosePublicKey()));
    }

}
