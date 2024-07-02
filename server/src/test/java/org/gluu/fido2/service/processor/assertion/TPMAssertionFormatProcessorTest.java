package org.gluu.fido2.service.processor.assertion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.PublicKey;

import org.gluu.fido2.exception.Fido2CompromisedDevice;
import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.service.AuthenticatorDataParser;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.util.DigestUtilService;
import org.gluu.fido2.service.util.HexUtilService;
import org.gluu.fido2.service.verifier.AuthenticatorDataVerifier;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.gluu.fido2.service.verifier.UserVerificationVerifier;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.gluu.persist.model.fido2.UserVerification;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

@ExtendWith(MockitoExtension.class)
class TPMAssertionFormatProcessorTest {

    @InjectMocks
    private TPMAssertionFormatProcessor tpmAssertionFormatProcessor;

    @Mock
    private Logger log;

    @Mock
    private CoseService coseService;

    @Mock
    private CommonVerifiers commonVerifiers;

    @Mock
    private AuthenticatorDataVerifier authenticatorDataVerifier;

    @Mock
    private UserVerificationVerifier userVerificationVerifier;

    @Mock
    private AuthenticatorDataParser authenticatorDataParser;

    @Mock
    private DataMapperService dataMapperService;

    @Mock
    private Base64Service base64Service;

    @Mock
    private DigestUtilService digestUtilService;

    @Mock
    private HexUtilService hexUtilService;

    @Test
    void getAttestationFormat_valid_tpm() {
        String fmt = tpmAssertionFormatProcessor.getAttestationFormat().getFmt();
        assertNotNull(fmt);
        assertEquals(fmt, "tpm");
    }

    @Test
    void process_ifAttestationRequestContainsPlatform_success() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain.test");
        when(registration.getAttenstationRequest()).thenReturn("{\"authenticator\": \"platform\"}");
        when(registration.getSignatureAlgorithm()).thenReturn(-1);
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);

        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(mock(AuthData.class));
        when(dataMapperService.cborReadTree(any())).thenReturn(mock(JsonNode.class));
        when(coseService.createUncompressedPointFromCOSEPublicKey(any())).thenReturn(mock(PublicKey.class));
        when(hexUtilService.encodeHexString(any())).thenReturn("publicKeyHex_test");

        tpmAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain.test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verify(base64Service).urlDecode(anyString());
        verify(digestUtilService).sha256Digest(any());
        verify(log).debug(eq("EC Public key hex {}"), eq("publicKeyHex_test"));
        verify(log).debug(eq("registration.getSignatureAlgorithm(): -1"));
        verify(log).debug(eq("Platform authenticator: -257"));
        verify(authenticatorDataVerifier).verifyAssertionSignature(any(), any(), any(), any(), eq(-257));
    }

    @Test
    void process_ifAttestationRequestDoesNotContainsPlatform_success() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain.test");
        when(registration.getAttenstationRequest()).thenReturn("{\"authenticator\": \"none\"}");
        when(registration.getSignatureAlgorithm()).thenReturn(-1);
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);

        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(mock(AuthData.class));
        when(dataMapperService.cborReadTree(any())).thenReturn(mock(JsonNode.class));
        when(coseService.createUncompressedPointFromCOSEPublicKey(any())).thenReturn(mock(PublicKey.class));
        when(hexUtilService.encodeHexString(any())).thenReturn("publicKeyHex_test");

        tpmAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain.test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verify(base64Service).urlDecode(anyString());
        verify(digestUtilService).sha256Digest(any());
        verify(log).debug(eq("EC Public key hex {}"), eq("publicKeyHex_test"));
        verify(log).debug(eq("registration.getSignatureAlgorithm(): -1"));
        verify(log).debug(eq("Platform authenticator: -1"));
        verify(authenticatorDataVerifier).verifyAssertionSignature(any(), any(), any(), any(), eq(-1));
    }

    @Test
    void process_ifVerifyCounterThrownError_fido2CompromisedDevice() {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain.test");
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);
        when(registration.getCounter()).thenReturn(1000);

        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(mock(AuthData.class));
        when(authenticatorDataParser.parseCounter(any())).thenReturn(500);
        doThrow(new Fido2CompromisedDevice("VerifyCounterError_test")).when(commonVerifiers).verifyCounter(anyInt(), anyInt());

        Fido2CompromisedDevice ex = assertThrows(Fido2CompromisedDevice.class, () -> tpmAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "VerifyCounterError_test");

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain.test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verify(base64Service).urlDecode(anyString());
        verify(authenticatorDataParser).parseCounter(any());

        verifyNoInteractions(dataMapperService, coseService, hexUtilService, authenticatorDataVerifier);
        verifyNoMoreInteractions(base64Service, log);
    }

    @Test
    void process_ifCborReadTreeThrownError_fido2RuntimeException() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain.test");
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);
        when(registration.getCounter()).thenReturn(1000);

        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(mock(AuthData.class));
        when(authenticatorDataParser.parseCounter(any())).thenReturn(500);
        when(dataMapperService.cborReadTree(any())).thenThrow(new IOException("cborReadTreeError_test"));

        Fido2RuntimeException ex = assertThrows(Fido2RuntimeException.class, () -> tpmAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Failed to check tpm assertion");

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain.test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verify(base64Service).urlDecode(anyString());
        verify(authenticatorDataParser).parseCounter(any());

        verifyNoInteractions(coseService, hexUtilService, authenticatorDataVerifier);
        verifyNoMoreInteractions(log);
    }
}
