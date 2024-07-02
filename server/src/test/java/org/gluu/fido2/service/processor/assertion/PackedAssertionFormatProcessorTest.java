package org.gluu.fido2.service.processor.assertion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.PublicKey;

import org.gluu.fido2.ctap.AuthenticatorAttachment;
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
class PackedAssertionFormatProcessorTest {

    @InjectMocks
    private PackedAssertionFormatProcessor packedAssertionFormatProcessor;

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
    void getAttestationFormat_valid_packed() {
        String fmt = packedAssertionFormatProcessor.getAttestationFormat().getFmt();
        assertNotNull(fmt);
        assertEquals(fmt, "packed");
    }

    @Test
    void process_ifAuthenticatorRequestIsPlatform_success() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain_test");
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);
        when(registration.getAttenstationRequest()).thenReturn(AuthenticatorAttachment.PLATFORM.getAttachment());
        when(registration.getSignatureAlgorithm()).thenReturn(-256);

        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(mock(AuthData.class));
        when(dataMapperService.cborReadTree(any())).thenReturn(mock(JsonNode.class));
        when(coseService.createUncompressedPointFromCOSEPublicKey(any())).thenReturn(mock(PublicKey.class));

        packedAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain_test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verify(base64Service).urlDecode(eq("clientDataJson_test"));
        verify(digestUtilService).sha256Digest(any());
        verify(authenticatorDataParser).parseCounter(any());
        verify(hexUtilService).encodeHexString(any());
        verify(log).debug(eq("registration.getSignatureAlgorithm(): -256"));
        verify(log).debug(eq("Platform authenticator: -7"));
        verify(authenticatorDataVerifier).verifyAssertionSignature(any(), any(), any(), any(), eq(-7));
    }

    @Test
    void process_ifAuthenticatorRequestIsNotPlatform_success() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain_test");
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);
        when(registration.getAttenstationRequest()).thenReturn("wrong_attestation_request");
        when(registration.getSignatureAlgorithm()).thenReturn(-256);

        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(mock(AuthData.class));
        when(dataMapperService.cborReadTree(any())).thenReturn(mock(JsonNode.class));
        when(coseService.createUncompressedPointFromCOSEPublicKey(any())).thenReturn(mock(PublicKey.class));

        packedAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity);

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain_test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verify(base64Service).urlDecode(eq("clientDataJson_test"));
        verify(digestUtilService).sha256Digest(any());
        verify(authenticatorDataParser).parseCounter(any());
        verify(hexUtilService).encodeHexString(any());
        verify(log).debug(eq("registration.getSignatureAlgorithm(): -256"));
        verify(log).debug(eq("Platform authenticator: -256"));
        verify(authenticatorDataVerifier).verifyAssertionSignature(any(), any(), any(), any(), eq(-256));
    }

    @Test
    void process_ifVerifyCounterThrowError_fido2CompromisedDevice() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain_test");
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);
        when(registration.getCounter()).thenReturn(1);

        AuthData authData = mock(AuthData.class);
        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(authData);
        doThrow(new Fido2CompromisedDevice("Fido2CompromisedDevice_test")).when(commonVerifiers).verifyCounter(anyInt(), anyInt());

        Fido2CompromisedDevice ex = assertThrows(Fido2CompromisedDevice.class, () -> packedAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Fido2CompromisedDevice_test");

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain_test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verifyNoInteractions(hexUtilService, dataMapperService, coseService, authenticatorDataVerifier);
        verifyNoMoreInteractions(log);
    }

    @Test
    void process_ifCborReadTreeThrowError_fido2RuntimeException() throws IOException {
        String base64AuthenticatorData = "base64AuthenticatorData_test";
        String signature = "signature_test";
        String clientDataJson = "clientDataJson_test";
        Fido2RegistrationData registration = mock(Fido2RegistrationData.class);
        Fido2AuthenticationData authenticationEntity = mock(Fido2AuthenticationData.class);

        when(registration.getDomain()).thenReturn("domain_test");
        when(authenticationEntity.getUserVerificationOption()).thenReturn(UserVerification.preferred);
        when(registration.getCounter()).thenReturn(1);

        AuthData authData = mock(AuthData.class);
        when(authenticatorDataParser.parseAssertionData(any())).thenReturn(authData);
        when(dataMapperService.cborReadTree(any())).thenThrow(new IOException("IOException_test"));

        Fido2RuntimeException ex = assertThrows(Fido2RuntimeException.class, () -> packedAssertionFormatProcessor.process(base64AuthenticatorData, signature, clientDataJson, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Failed to check packet assertion");

        verify(commonVerifiers).verifyRpIdHash(any(), eq("domain_test"));
        verify(log).debug(eq("User verification option {}"), eq(UserVerification.preferred));
        verify(userVerificationVerifier).verifyUserVerificationOption(eq(UserVerification.preferred), any());
        verifyNoInteractions(hexUtilService, coseService, authenticatorDataVerifier);
        verifyNoMoreInteractions(log);
    }
}
