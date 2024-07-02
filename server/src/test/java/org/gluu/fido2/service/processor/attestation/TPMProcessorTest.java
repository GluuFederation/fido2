package org.gluu.fido2.service.processor.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.conf.Fido2Configuration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CertificateService;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.mds.AttestationCertificateService;
import org.gluu.fido2.service.verifier.CertificateVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.fido2.service.verifier.SignatureVerifier;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import tss.tpm.TPMS_ATTEST;
import tss.tpm.TPMT_PUBLIC;

@ExtendWith(MockitoExtension.class)
class TPMProcessorTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    @InjectMocks
    private TPMProcessor tpmProcessor;

    @Mock
    private Logger log;

    @Mock
    private CertificateService certificateService;

    @Mock
    private CommonVerifiers commonVerifiers;

    @Mock
    private AttestationCertificateService attestationCertificateService;

    @Mock
    private SignatureVerifier signatureVerifier;

    @Mock
    private CertificateVerifier certificateVerifier;

    @Mock
    private DataMapperService dataMapperService;

    @Mock
    private Base64Service base64Service;

    @Mock
    private AppConfiguration appConfiguration;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Test
    void getAttestationFormat_valid_tpm() {
        String fmt = tpmProcessor.getAttestationFormat().getFmt();
        assertNotNull(fmt);
        assertEquals(fmt, "tpm");
    }

    @Test
    void process_ifCborReadTreeThrowError_fido2RuntimeException() throws IOException {
        ObjectNode attStmt = mapper.createObjectNode();
        AuthData authData = new AuthData();
        authData.setCosePublicKey("test-cosePublicKey".getBytes());
        Fido2RegistrationData registration = new Fido2RegistrationData();
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        when(dataMapperService.cborReadTree(any())).thenThrow(new IOException("test IOException"));
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> tpmProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(dataMapperService).cborReadTree(any(byte[].class));
        verify(errorResponseFactory).badRequestException(any(), eq("Problem with TPM attestation: test IOException"));
        verifyNoInteractions(base64Service, certificateService, attestationCertificateService, certificateVerifier, appConfiguration, log, commonVerifiers, signatureVerifier);
    }

    @Test
    void process_ifX5cIsEmpty_badRequestException() throws IOException {
        ObjectNode attStmt = mapper.createObjectNode();
        ArrayNode x5cArray = mapper.createArrayNode();
        attStmt.set("x5c", x5cArray);
        attStmt.put("pubArea", "test-pubArea");
        attStmt.put("certInfo", "test-certInfo");
        attStmt.put("ver", "2.0");
        attStmt.put("alg", -256);
        AuthData authData = new AuthData();
        authData.setCosePublicKey("test-cosePublicKey".getBytes());
        authData.setAttestationBuffer("test-attestationBuffer".getBytes());
        Fido2RegistrationData registration = new Fido2RegistrationData();
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        ObjectNode cborPublicKey = mapper.createObjectNode();
        cborPublicKey.put("-1", "test-PublicKey");
        when(dataMapperService.cborReadTree(any())).thenReturn(cborPublicKey);
        MessageDigest messageDigest = mock(MessageDigest.class);
        when(signatureVerifier.getDigest(-256)).thenReturn(messageDigest);
        when(messageDigest.digest()).thenReturn("test-hashedBuffer".getBytes());
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> tpmProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(dataMapperService).cborReadTree(any(byte[].class));
        verify(base64Service).decode(any(String.class));
        verifyNoInteractions(certificateService, attestationCertificateService, certificateVerifier, appConfiguration, commonVerifiers);
    }

    @Test
    void process_ifX5cAndSkipValidateMdsInAttestationIsFalseAndVerifyAttestationCertificatesThrowError_badRequestException() throws IOException {
        ObjectNode attStmt = mapper.createObjectNode();
        ArrayNode x5cArray = mapper.createArrayNode();
        x5cArray.add("certPath1");
        attStmt.set("x5c", x5cArray);
        attStmt.put("pubArea", "test-pubArea");
        attStmt.put("certInfo", "test-certInfo");
        attStmt.put("ver", "2.0");
        attStmt.put("alg", -256);
        AuthData authData = new AuthData();
        authData.setCosePublicKey("test-cosePublicKey".getBytes());
        authData.setAttestationBuffer("test-attestationBuffer".getBytes());
        Fido2RegistrationData registration = new Fido2RegistrationData();
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(false);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        ObjectNode cborPublicKey = mapper.createObjectNode();
        cborPublicKey.put("-1", "test-PublicKey");
        when(dataMapperService.cborReadTree(any())).thenReturn(cborPublicKey);
        MessageDigest messageDigest = mock(MessageDigest.class);
        when(signatureVerifier.getDigest(-256)).thenReturn(messageDigest);
        when(messageDigest.digest()).thenReturn("test-hashedBuffer".getBytes());
        List<X509Certificate> aikCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(Collections.emptyList());
        when(certificateService.getCertificates(anyList())).thenReturn(aikCertificates);
        when(certificateVerifier.verifyAttestationCertificates(anyList(), anyList())).thenThrow(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException res = assertThrows(WebApplicationException.class, () -> tpmProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters));
        assertNotNull(res);
        assertNotNull(res.getResponse());
        assertEquals(res.getResponse().getStatus(), 400);
        assertEquals(res.getResponse().getEntity(), "test exception");

        verify(log, never()).warn("SkipValidateMdsInAttestation is enabled");
        verify(dataMapperService).cborReadTree(any(byte[].class));
        verify(base64Service).decode(any(String.class));
        verify(attestationCertificateService).getAttestationRootCertificates(authData, aikCertificates);
        verify(certificateVerifier).verifyAttestationCertificates(any(), any());
        verifyNoInteractions(commonVerifiers);
    }

    @Test
    void process_ifX5cAndSkipValidateMdsInAttestationIsFalseAndVerifyAttestationCertificatesIsValid_success() throws IOException {
        ObjectNode attStmt = mapper.createObjectNode();
        ArrayNode x5cArray = mapper.createArrayNode();
        x5cArray.add("certPath1");
        attStmt.set("x5c", x5cArray);
        String pubArea = "AAEACwAGBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAEAgAAAAAAAEAss+GHGDpvFEbV+MsBvJsXWTC4MKkyZoOFYCM2EF05SNlFZs4PMQWX1b13Rg0jz77aH3sMO2YmqOSmU00l6/yRabVSiRoAtmRl5pY3HJ+WRsjl//zaJmeHi3EWxUFPA7xAE+qecX7s4HW6aDDQZZgFAfSh95exV1CStYT3s9YvBg/PT3C6355hfK2TAdMqTGXvKRolqmQ8+hO8qMg9b73MXLneMEAp0d2vjufcH8nVvtcu72z9cke7yqmsKRuWg8BpV0r36Ji2UvzPElcdzylAm1n2oGn/POdkf8bQcCI48oc5QRAUoDiSOTuXlybUF0iIi/jOUFfhGnTB6vkwRNZ3w==";
        String certInfo = "/1RDR4AXACIACxHmjtRNtTcuFCluL4Ssx4OYdRiBkh4w/CKgb4tzx5RTACAzhxi3W0HuExVoYbtvYBWeg7Bli9xEDJvw2AMqf60mywAAAAFHcBdIVWl7S8aFYKUBc375jTRWVfsAIgALzYHYUq0K55IskuzIfukQ/H/o1LOOjz7EoGnTf6Yy8toAIgALfXLmQ1rhTAPBOQeQbAQQYPqvbON0RO/9OtVFOrp7UV4=";
        attStmt.put("pubArea", pubArea);
        attStmt.put("certInfo", certInfo);
        attStmt.put("ver", "2.0");
        attStmt.put("alg", -256);
        AuthData authData = new AuthData();
        authData.setCosePublicKey("test-cosePublicKey".getBytes());
        authData.setAttestationBuffer("test-attestationBuffer".getBytes());
        Fido2RegistrationData registration = new Fido2RegistrationData();
        byte[] clientDataHash = "test-clientDataHash".getBytes();
        CredAndCounterData credIdAndCounters = new CredAndCounterData();
        byte[] certInfoBuffer = Base64.getDecoder().decode(certInfo);
        byte[] pubAreaBuffer = Base64.getDecoder().decode(pubArea);
        TPMS_ATTEST tpmsAttest = TPMS_ATTEST.fromTpm(certInfoBuffer);
        TPMT_PUBLIC tpmtPublic = TPMT_PUBLIC.fromTpm(pubAreaBuffer);
        ObjectNode cborPublicKey = mapper.createObjectNode();
        cborPublicKey.put("-1", "test-PublicKey");
        Fido2Configuration fido2Configuration = new Fido2Configuration();
        fido2Configuration.setSkipValidateMdsInAttestationEnabled(false);
        when(appConfiguration.getFido2Configuration()).thenReturn(fido2Configuration);
        when(dataMapperService.cborReadTree(any())).thenReturn(cborPublicKey);
        MessageDigest messageDigest = mock(MessageDigest.class);
        when(signatureVerifier.getDigest(-256)).thenReturn(messageDigest);
        when(messageDigest.digest()).thenReturn(tpmsAttest.extraData);
        List<X509Certificate> aikCertificates = Collections.singletonList(mock(X509Certificate.class));
        when(certificateService.getCertificates(anyList())).thenReturn(Collections.emptyList());
        when(certificateService.getCertificates(anyList())).thenReturn(aikCertificates);
        X509Certificate verifiedCert = mock(X509Certificate.class);
        when(certificateVerifier.verifyAttestationCertificates(anyList(), anyList())).thenReturn(verifiedCert);
        when(commonVerifiers.verifyBase64String(any())).thenReturn("test-signature");
        when(base64Service.decode(any(String.class))).thenReturn(Arrays.copyOfRange(tpmtPublic.unique.toTpm(), 2, tpmtPublic.unique.toTpm().length), certInfoBuffer, pubAreaBuffer);
        when(commonVerifiers.tpmParseToPublic(any())).thenReturn(tpmtPublic);
        when(commonVerifiers.tpmParseToAttest(any())).thenReturn(tpmsAttest);

        tpmProcessor.process(attStmt, authData, registration, clientDataHash, credIdAndCounters);
        verify(dataMapperService).cborReadTree(any(byte[].class));
        verify(base64Service, times(3)).decode(anyString());
        verify(certificateService, times(2)).getCertificates(anyList());
        verify(attestationCertificateService).getAttestationRootCertificates(any(AuthData.class), anyList());
        verify(appConfiguration).getFido2Configuration();
        verify(log).trace("TPM attStmt 'alg': {}", -256);
        verify(base64Service, times(2)).urlEncodeToString(any());
        verifyNoMoreInteractions(log);
    }
}
