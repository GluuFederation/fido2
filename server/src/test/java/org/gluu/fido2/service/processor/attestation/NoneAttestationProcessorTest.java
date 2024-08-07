package org.gluu.fido2.service.processor.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.gluu.fido2.exception.Fido2RuntimeException;
import org.gluu.fido2.model.auth.AuthData;
import org.gluu.fido2.model.auth.CredAndCounterData;
import org.gluu.fido2.service.Base64Service;
import org.gluu.persist.model.fido2.Fido2RegistrationData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

@ExtendWith(MockitoExtension.class)
class NoneAttestationProcessorTest {

    @InjectMocks
    private NoneAttestationProcessor noneAttestationProcessor;

    @Mock
    private Logger log;

    @Mock
    private Base64Service base64Service;

    @Test
    void getAttestationFormat_valid_none() {
        String fmt = noneAttestationProcessor.getAttestationFormat().getFmt();
        assertNotNull(fmt);
        assertEquals(fmt, "none");
    }

    @Test
    void process_validData_success() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "clientDataHash_test".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        when(attStmt.isEmpty()).thenReturn(true);
        when(authData.getCredId()).thenReturn("credId_test".getBytes());
        when(authData.getCosePublicKey()).thenReturn("cosePublicKey_test".getBytes());

        noneAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters);

        verify(log).debug(eq("None/Surrogate attestation {}"), any(JsonNode.class));
        verify(base64Service, times(2)).urlEncodeToString(any(byte[].class));

        verify(log, never()).error(eq("Problem with None/Surrogate attestation"));
    }

    @Test
    void process_ifAttStmtIsEmptyFalse_fido2RuntimeException() {
        JsonNode attStmt = mock(JsonNode.class);
        AuthData authData = mock(AuthData.class);
        Fido2RegistrationData credential = mock(Fido2RegistrationData.class);
        byte[] clientDataHash = "clientDataHash_test".getBytes();
        CredAndCounterData credIdAndCounters = mock(CredAndCounterData.class);

        when(attStmt.isEmpty()).thenReturn(false);

        Fido2RuntimeException ex = assertThrows(Fido2RuntimeException.class, () -> noneAttestationProcessor.process(attStmt, authData, credential, clientDataHash, credIdAndCounters));
        assertNotNull(ex);
        assertEquals(ex.getMessage(), "Problem with None/Surrogate attestation");

        verify(log).debug(eq("None/Surrogate attestation {}"), any(JsonNode.class));
        verify(log).error(eq("Problem with None/Surrogate attestation"));

        verifyNoInteractions(base64Service);
    }
}
