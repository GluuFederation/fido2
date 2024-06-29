package org.gluu.fido2.service.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.service.processor.assertion.AssertionProcessorFactory;
import org.gluu.fido2.service.processors.AssertionFormatProcessor;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

@ExtendWith(MockitoExtension.class)
class AssertionVerifierTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @InjectMocks
    private AssertionVerifier assertionVerifier;

    @Mock
    private Logger log;

    @Mock
    private AssertionProcessorFactory assertionProcessorFactory;

    @Test
    void verifyAuthenticatorAssertionResponse_authenticatorDataIsNull_fido2RuntimeException() {
        ObjectNode response = mapper.createObjectNode();
        response.put("clientDataJSON", "TEST-clientDataJSON");
        response.put("signature", "TEST-signature");
        Fido2RegistrationData registration = new Fido2RegistrationData();
        Fido2AuthenticationData authenticationEntity = new Fido2AuthenticationData();

        Fido2RuntimeException ex = assertThrows(Fido2RuntimeException.class, () -> assertionVerifier.verifyAuthenticatorAssertionResponse(response, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Authenticator data is invalid");
        verifyNoInteractions(log, assertionProcessorFactory);
    }

    @Test
    void verifyAuthenticatorAssertionResponse_clientDataJSONIsNull_fido2RuntimeException() {
        ObjectNode response = mapper.createObjectNode();
        response.put("authenticatorData", "TEST-authenticatorData");
        response.put("signature", "TEST-signature");
        Fido2RegistrationData registration = new Fido2RegistrationData();
        Fido2AuthenticationData authenticationEntity = new Fido2AuthenticationData();

        Fido2RuntimeException ex = assertThrows(Fido2RuntimeException.class, () -> assertionVerifier.verifyAuthenticatorAssertionResponse(response, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Authenticator data is invalid");
        verifyNoInteractions(log, assertionProcessorFactory);
    }

    @Test
    void verifyAuthenticatorAssertionResponse_signatureIsNull_fido2RuntimeException() {
        ObjectNode response = mapper.createObjectNode();
        response.put("authenticatorData", "TEST-authenticatorData");
        response.put("clientDataJSON", "TEST-clientDataJSON");
        Fido2RegistrationData registration = new Fido2RegistrationData();
        Fido2AuthenticationData authenticationEntity = new Fido2AuthenticationData();

        Fido2RuntimeException ex = assertThrows(Fido2RuntimeException.class, () -> assertionVerifier.verifyAuthenticatorAssertionResponse(response, registration, authenticationEntity));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Authenticator data is invalid");
        verifyNoInteractions(log, assertionProcessorFactory);
    }

    @Test
    void verifyAuthenticatorAssertionResponse_validValues_valid() {
        ObjectNode response = mapper.createObjectNode();
        String authenticatorDataValue = "TEST-authenticatorData";
        String clientDataJSONValue = "TEST-clientDataJSON";
        String signatureValue = "TEST-signature";
        response.put("authenticatorData", authenticatorDataValue);
        response.put("clientDataJSON", clientDataJSONValue);
        response.put("signature", signatureValue);
        Fido2RegistrationData registration = new Fido2RegistrationData();
        Fido2AuthenticationData authenticationEntity = new Fido2AuthenticationData();
        AssertionFormatProcessor assertionProcessor = mock(AssertionFormatProcessor.class);
        when(assertionProcessorFactory.getCommandProcessor(registration.getAttestationType())).thenReturn(assertionProcessor);

        assertionVerifier.verifyAuthenticatorAssertionResponse(response, registration, authenticationEntity);
        verify(log).debug("Authenticator data {}", authenticatorDataValue);
        verify(assertionProcessor).process(authenticatorDataValue, signatureValue, clientDataJSONValue, registration, authenticationEntity);
    }
}
