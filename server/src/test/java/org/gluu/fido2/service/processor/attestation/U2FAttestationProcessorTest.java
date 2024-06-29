package org.gluu.fido2.service.processor.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.nio.file.attribute.UserPrincipal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.gluu.fido2.exception.Fido2MissingAttestationCertException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.conf.Fido2Configuration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CertificateService;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.mds.AttestationCertificateService;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CertificateVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.fido2.service.verifier.UserVerificationVerifier;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;

@ExtendWith(MockitoExtension.class)
class U2FAttestationProcessorTest {

    @InjectMocks
    private U2FAttestationProcessor u2FAttestationProcessor;

    @Mock
    private Logger log;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private CommonVerifiers commonVerifiers;

    @Mock
    private AuthenticatorDataVerifier authenticatorDataVerifier;

    @Mock
    private UserVerificationVerifier userVerificationVerifier;

    @Mock
    private AttestationCertificateService attestationCertificateService;

    @Mock
    private CertificateVerifier certificateVerifier;

    @Mock
    private CoseService coseService;

    @Mock
    private Base64Service base64Service;

    @Mock
    private CertificateService certificateService;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Test
    void getAttestationFormat_valid_fidoU2f() {
        String fmt = u2FAttestationProcessor.getAttestationFormat().getFmt();
        assertNotNull(fmt);
        assertEquals(fmt, "fido-u2f");
    }

    @Test
    void process_ifAttStmtHasX5cAndSkipValidateMdsInAttestationIsFalseAndVerifyAttestationThrowErrorAndCertificatesIsEmpty_fido2MissingAttestationCertException() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = new byte[]{};
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);
        Fido2Configuration fido2Configuration = mock(Fido2Configuration.class);
        JsonNode x5cNode = mock(JsonNode.class);
        when(registration.getDomain()).thenReturn("test-domain");
        when(attStmt.hasNonNull("x5c")).thenReturn(true);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.emptyIterator());
        when(attStmt.get("sig")).thenReturn(mock(JsonNode.class));
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");
        when(certificateVerifier.verifyAttestationCertificates(any(), any())).thenThrow(new Fido2MissingAttestationCertException("test missing"));
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(fido2Configuration.isSkipValidateMdsInAttestationEnabled()).thenReturn(false);
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> u2FAttestationProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");
//        assertNotNull(ex);
//        assertEquals(ex.getMessage(), "test missing");

        verify(commonVerifiers).verifyAAGUIDZeroed(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(commonVerifiers).verifyRpIdHash(authData, "test-domain");
        verify(certificateService).getCertificates(anyList());
        verify(attestationCertificateService).getAttestationRootCertificates((JsonNode) eq(null), anyList());
        verify(appConfiguration).getFido2Configuration();
        verify(certificateVerifier).verifyAttestationCertificates(anyList(), anyList());
        verify(authenticatorDataVerifier, never()).verifyU2FAttestationSignature(any(AuthData.class), any(byte[].class), any(String.class), any(X509Certificate.class), any(Integer.class));
        verify(log, never()).warn(contains("Failed to find attestation validation signature public certificate with DN"), anyString());
        verifyNoInteractions(log, authenticatorDataVerifier, coseService, base64Service);
    }

    @Test
    void process_ifAttStmtHasX5cAndSkipValidateMdsInAttestationIsFalseAndVerifyAttestationThrowErrorAndCertificatesIsNotEmpty_badRequestException() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = new byte[]{};
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);
        Fido2Configuration fido2Configuration = mock(Fido2Configuration.class);
        JsonNode x5cNode = mock(JsonNode.class);
        when(registration.getDomain()).thenReturn("test-domain");
        when(attStmt.hasNonNull("x5c")).thenReturn(true);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.singletonList((JsonNode) new TextNode("cert1")).iterator());
        when(attStmt.get("sig")).thenReturn(mock(JsonNode.class));
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");
        when(certificateVerifier.verifyAttestationCertificates(any(), any())).thenThrow(new Fido2MissingAttestationCertException("test missing"));
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(fido2Configuration.isSkipValidateMdsInAttestationEnabled()).thenReturn(false);
        X509Certificate publicCert1 = mock(X509Certificate.class);
        when(certificateService.getCertificates(anyList())).thenReturn(Collections.singletonList(publicCert1));
        when(publicCert1.getIssuerDN()).thenReturn((UserPrincipal) () -> "test-issuer");
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> u2FAttestationProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(commonVerifiers).verifyAAGUIDZeroed(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(commonVerifiers).verifyRpIdHash(authData, "test-domain");
        verify(certificateService).getCertificates(anyList());
        verify(attestationCertificateService).getAttestationRootCertificates((JsonNode) eq(null), anyList());
        verify(appConfiguration).getFido2Configuration();
        verify(certificateVerifier).verifyAttestationCertificates(anyList(), anyList());
        verify(authenticatorDataVerifier, never()).verifyU2FAttestationSignature(any(AuthData.class), any(byte[].class), any(String.class), any(X509Certificate.class), any(Integer.class));
        verify(log).warn("Failed to find attestation validation signature public certificate with DN: '{}'", "test-issuer");
        verifyNoInteractions(authenticatorDataVerifier, coseService, base64Service);
    }

    @Test
    void process_ifAttStmtHasX5cAndSkipValidateMdsInAttestationIsFalseAndCertificatesIsNotEmptyAndVerifyAttestationIsValid_success() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = new byte[]{};
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);
        Fido2Configuration fido2Configuration = mock(Fido2Configuration.class);
        JsonNode x5cNode = mock(JsonNode.class);
        when(registration.getDomain()).thenReturn("test-domain");
        when(attStmt.hasNonNull("x5c")).thenReturn(true);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.singletonList((JsonNode) new TextNode("cert1")).iterator());
        when(attStmt.get("sig")).thenReturn(mock(JsonNode.class));
        X509Certificate verifiedCert = mock(X509Certificate.class);
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");
        when(certificateVerifier.verifyAttestationCertificates(any(), any())).thenReturn(verifiedCert);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(fido2Configuration.isSkipValidateMdsInAttestationEnabled()).thenReturn(false);

        u2FAttestationProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters);
        verify(commonVerifiers).verifyAAGUIDZeroed(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(commonVerifiers).verifyRpIdHash(authData, "test-domain");
        verify(certificateService).getCertificates(anyList());
        verify(attestationCertificateService).getAttestationRootCertificates((JsonNode) eq(null), anyList());
        verify(certificateVerifier).verifyAttestationCertificates(anyList(), anyList());
        verify(authenticatorDataVerifier).verifyU2FAttestationSignature(any(AuthData.class), any(byte[].class), any(String.class), any(X509Certificate.class), any(Integer.class));
        verify(base64Service, times(2)).urlEncodeToString(any());
        verifyNoInteractions(log, coseService);
    }

    @Test
    void process_ifAttStmtHasX5cAndSkipValidateMdsInAttestationIsTrue_success() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = new byte[]{};
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);
        Fido2Configuration fido2Configuration = mock(Fido2Configuration.class);
        JsonNode x5cNode = mock(JsonNode.class);
        when(registration.getDomain()).thenReturn("test-domain");
        when(attStmt.hasNonNull("x5c")).thenReturn(true);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.singletonList((JsonNode) new TextNode("cert1")).iterator());
        when(attStmt.get("sig")).thenReturn(mock(JsonNode.class));
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(fido2Configuration.isSkipValidateMdsInAttestationEnabled()).thenReturn(true);

        u2FAttestationProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters);
        verify(commonVerifiers).verifyAAGUIDZeroed(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(commonVerifiers).verifyRpIdHash(authData, "test-domain");
        verify(certificateService).getCertificates(anyList());
        verify(attestationCertificateService).getAttestationRootCertificates((JsonNode) eq(null), anyList());
        verify(log).warn(eq("SkipValidateMdsInAttestation is enabled"));
        verifyNoMoreInteractions(log);
        verify(base64Service, times(2)).urlEncodeToString(any());
        verifyNoInteractions(certificateVerifier, authenticatorDataVerifier, coseService);
    }

    @Test
    void process_ifAttStmtHasEcdaaKeyId_badRequestException() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = new byte[]{};
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);
        when(registration.getDomain()).thenReturn("test-domain");
        when(attStmt.get("sig")).thenReturn(mock(JsonNode.class));
        when(attStmt.hasNonNull("x5c")).thenReturn(false);
        when(attStmt.hasNonNull("ecdaaKeyId")).thenReturn(true);
        when(attStmt.get("ecdaaKeyId")).thenReturn(new TextNode("test-ecdaaKeyId"));
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> u2FAttestationProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(commonVerifiers).verifyBase64String(any());
        verify(commonVerifiers).verifyAAGUIDZeroed(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(commonVerifiers).verifyRpIdHash(authData, "test-domain");
        verify(log).warn("Fido-U2F unsupported EcdaaKeyId: {}", "test-ecdaaKeyId");
        verifyNoMoreInteractions(log);
        verifyNoInteractions(certificateService, certificateVerifier, appConfiguration, attestationCertificateService, authenticatorDataVerifier, coseService, base64Service);
    }

    @Test
    void process_ifAttStmtNotIsX5cOrEcdaaKeyId_success() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = new byte[]{};
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);
        when(registration.getDomain()).thenReturn("test-domain");
        when(authData.getAuthDataDecoded()).thenReturn("test-decoded".getBytes());
        when(attStmt.get("sig")).thenReturn(mock(JsonNode.class));
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");
        when(attStmt.hasNonNull("x5c")).thenReturn(false);
        when(attStmt.hasNonNull("ecdaaKeyId")).thenReturn(false);
        PublicKey publicKey = mock(PublicKey.class);
        when(coseService.getPublicKeyFromUncompressedECPoint(any())).thenReturn(publicKey);

        u2FAttestationProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters);
        verify(commonVerifiers).verifyBase64String(any());
        verify(commonVerifiers).verifyAAGUIDZeroed(authData);
        verify(userVerificationVerifier).verifyUserPresent(authData);
        verify(commonVerifiers).verifyRpIdHash(authData, "test-domain");
        verify(coseService).getPublicKeyFromUncompressedECPoint(any());
        verify(authenticatorDataVerifier).verifyPackedSurrogateAttestationSignature(authData.getAuthDataDecoded(), clientDataHash, "test-signature", publicKey, -7);
        verifyNoInteractions(log, certificateService, certificateVerifier, appConfiguration, attestationCertificateService);
    }
}
