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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.gluu.fido2.androind.AndroidKeyUtils;
import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.conf.Fido2Configuration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CertificateService;
import org.gluu.fido2.service.mds.AttestationCertificateService;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CertificateVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

@ExtendWith(MockitoExtension.class)
class AndroidKeyAttestationProcessorTest {

    @InjectMocks
    private AndroidKeyAttestationProcessor androidKeyAttestationProcessor;

    @Mock
    private Logger log;

    @Mock
    private CommonVerifiers commonVerifiers;

    @Mock
    private AuthenticatorDataVerifier authenticatorDataVerifier;

    @Mock
    private CertificateService certificateService;

    @Mock
    private CertificateVerifier certificateVerifier;

    @Mock
    private AndroidKeyUtils androidKeyUtils;

    @Mock
    private AttestationCertificateService attestationCertificateService;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private Base64Service base64Service;

    @Test
    void getAttestationFormat_valid_androidKey() {
        String fmt = androidKeyAttestationProcessor.getAttestationFormat().getFmt();
        assertNotNull(fmt);
        assertEquals(fmt, "android-key");
    }

    @Test
    void process_ifSkipValidateMdsInAttestationEnabledIsTrue_valid() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        JsonNode x5cNode = mock(JsonNode.class);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.emptyIterator());
        List<X509Certificate> certificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(certificates);
        List<X509Certificate> trustAnchorCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(attestationCertificateService.getAttestationRootCertificates(authData, certificates)).thenReturn(trustAnchorCertificates);
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(true);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(base64Service.urlEncodeToString(any())).thenReturn("test-credId");

        androidKeyAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters);

        verify(log).debug(eq("Android-key payload"));
        verify(attestationCertificateService).getAttestationRootCertificates(authData, certificates);
        verify(appConfiguration).getFido2Configuration();
        verify(log).warn(eq("SkipValidateMdsInAttestation is enabled"));
        verify(base64Service, times(2)).urlEncodeToString(any());
        verifyNoMoreInteractions(log);
        verifyNoInteractions(certificateVerifier, errorResponseFactory, androidKeyUtils, commonVerifiers, authenticatorDataVerifier);
    }

    @Test
    void process_ifVerifyAttestationCertificatesThrownError_badRequestException() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        JsonNode x5cNode = mock(JsonNode.class);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.emptyIterator());
        List<X509Certificate> certificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(certificates);
        List<X509Certificate> trustAnchorCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(attestationCertificateService.getAttestationRootCertificates(authData, certificates)).thenReturn(trustAnchorCertificates);
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(false);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        Fido2RuntimeException fido2RuntimeException = new Fido2RuntimeException("test exception");
        when(certificateVerifier.verifyAttestationCertificates(certificates, trustAnchorCertificates)).thenThrow(fido2RuntimeException);
        when(errorResponseFactory.badRequestException(any(), any())).thenThrow(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> androidKeyAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(log).debug(eq("Android-key payload"));
//        verify(certificateService).getCertificates(anyList());
        verify(attestationCertificateService).getAttestationRootCertificates(authData, certificates);
        verify(appConfiguration).getFido2Configuration();
        verify(certificateVerifier).verifyAttestationCertificates(certificates, trustAnchorCertificates);
        verify(log).error("Error on verify attestation certificates: {}", fido2RuntimeException.getMessage(), fido2RuntimeException);
        verify(errorResponseFactory).badRequestException(any(), any());
        verifyNoMoreInteractions(log, errorResponseFactory);
        verifyNoInteractions(base64Service, androidKeyUtils, commonVerifiers, authenticatorDataVerifier);
    }

    @Test
    void process_ifClientDataHashNotEqualsToAttestationChallenge_badRequestException() throws Exception {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        JsonNode x5cNode = mock(JsonNode.class);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.emptyIterator());
        List<X509Certificate> certificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(certificates);
        List<X509Certificate> trustAnchorCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(attestationCertificateService.getAttestationRootCertificates(authData, certificates)).thenReturn(trustAnchorCertificates);
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(false);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(certificateVerifier.verifyAttestationCertificates(any(), any())).thenReturn(mock(X509Certificate.class));
        ASN1Sequence extensionData = mock(ASN1Sequence.class);
        when(androidKeyUtils.extractAttestationSequence(any())).thenReturn(extensionData);
        ASN1Integer asn1Integer = new ASN1Integer(1L);
        when(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_VERSION_INDEX)).thenReturn(asn1Integer);
        when(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_SECURITY_LEVEL_INDEX)).thenReturn(asn1Integer);
        when(extensionData.getObjectAt(AndroidKeyUtils.KEYMASTER_SECURITY_LEVEL_INDEX)).thenReturn(asn1Integer);
        ASN1OctetString asn1OctetString = mock(ASN1OctetString.class);
        when(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_CHALLENGE_INDEX)).thenReturn(asn1OctetString);
        when(asn1OctetString.getOctets()).thenReturn("test-octets".getBytes());
        when(errorResponseFactory.badRequestException(any(), any())).thenThrow(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> androidKeyAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(log).debug(eq("Android-key payload"));
        verify(attestationCertificateService).getAttestationRootCertificates(authData, certificates);
        verify(appConfiguration).getFido2Configuration();
        verify(certificateVerifier).verifyAttestationCertificates(certificates, trustAnchorCertificates);
        verify(androidKeyUtils).extractAttestationSequence(any());
        verify(errorResponseFactory).badRequestException(any(), eq("Invalid android key attestation"));
        verifyNoMoreInteractions(log, errorResponseFactory);
        verifyNoInteractions(base64Service, commonVerifiers, authenticatorDataVerifier);
    }

    @Test
    void process_ifCertificateServiceThrowError_badRequestException() throws Exception {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        JsonNode x5cNode = mock(JsonNode.class);
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(Collections.emptyIterator());
        List<X509Certificate> certificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(certificates);
        List<X509Certificate> trustAnchorCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(attestationCertificateService.getAttestationRootCertificates(authData, certificates)).thenReturn(trustAnchorCertificates);
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(false);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(androidKeyUtils.extractAttestationSequence(any())).thenThrow(new Exception("test exception"));
        when(errorResponseFactory.badRequestException(any(), any())).thenThrow(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> androidKeyAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(log).debug(eq("Android-key payload"));
        verify(attestationCertificateService).getAttestationRootCertificates(authData, certificates);
        verify(appConfiguration).getFido2Configuration();
        verify(certificateVerifier).verifyAttestationCertificates(certificates, trustAnchorCertificates);
        verify(log).warn(contains("Problem with android key"), anyString());
        verify(errorResponseFactory).badRequestException(any(), eq("Problem with android key"));
        verifyNoInteractions(commonVerifiers, authenticatorDataVerifier);
        verifyNoMoreInteractions(log, errorResponseFactory);
    }

    @Test
    void process_ifX5cContainsValues_valid() throws Exception {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "test-octets".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        when(authData.getKeyType()).thenReturn(1);
        JsonNode x5cNode = mock(JsonNode.class);
        List<JsonNode> elements = Arrays.asList(mock(JsonNode.class), mock(JsonNode.class));
        when(attStmt.get("x5c")).thenReturn(x5cNode);
        when(x5cNode.elements()).thenReturn(elements.iterator());
        List<X509Certificate> certificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(certificates);
        List<X509Certificate> trustAnchorCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(attestationCertificateService.getAttestationRootCertificates(authData, certificates)).thenReturn(trustAnchorCertificates);
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(false);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        X509Certificate verifiedCert = mock(X509Certificate.class);
        when(certificateVerifier.verifyAttestationCertificates(any(), any())).thenReturn(verifiedCert);
        ASN1Sequence extensionData = mock(ASN1Sequence.class);
        when(androidKeyUtils.extractAttestationSequence(any())).thenReturn(extensionData);
        ASN1Integer asn1Integer = new ASN1Integer(1L);
        when(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_VERSION_INDEX)).thenReturn(asn1Integer);
        when(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_SECURITY_LEVEL_INDEX)).thenReturn(asn1Integer);
        when(extensionData.getObjectAt(AndroidKeyUtils.KEYMASTER_SECURITY_LEVEL_INDEX)).thenReturn(asn1Integer);
        ASN1OctetString asn1OctetString = mock(ASN1OctetString.class);
        when(extensionData.getObjectAt(AndroidKeyUtils.ATTESTATION_CHALLENGE_INDEX)).thenReturn(asn1OctetString);
        when(asn1OctetString.getOctets()).thenReturn("test-octets".getBytes());
        ASN1Sequence asn1Sequence = mock(ASN1Sequence.class);
        when(extensionData.getObjectAt(AndroidKeyUtils.SW_ENFORCED_INDEX)).thenReturn(asn1Sequence);
        when(extensionData.getObjectAt(AndroidKeyUtils.TEE_ENFORCED_INDEX)).thenReturn(asn1Sequence);
        when(asn1Sequence.toArray()).thenReturn(new ASN1Encodable[]{mock(ASN1Encodable.class)});
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");

        androidKeyAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters);

        verify(log).debug(eq("Android-key payload"));
        verify(attestationCertificateService).getAttestationRootCertificates(authData, certificates);
        verify(appConfiguration).getFido2Configuration();
        verify(certificateVerifier).verifyAttestationCertificates(certificates, trustAnchorCertificates);
        verify(androidKeyUtils).extractAttestationSequence(any());
        verify(authenticatorDataVerifier).verifyAttestationSignature(authData, clientDataHash, "test-signature", verifiedCert, 1);
        verifyNoInteractions(errorResponseFactory);
        verifyNoMoreInteractions(log);
    }
}
