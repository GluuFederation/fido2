package org.gluu.fido2.service.sg.converter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.Base64Service;
import org.gluu.fido2.service.CoseService;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.DigestService;
import org.gluu.fido2.service.operation.AttestationService;
import org.gluu.fido2.service.persist.UserSessionIdService;
import org.gluu.fido2.service.sg.RawRegistrationService;
import org.gluu.oxauth.model.fido.u2f.message.RawRegisterResponse;
import org.gluu.oxauth.model.fido.u2f.protocol.RegisterResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
@ExtendWith(MockitoExtension.class)
class AttestationSuperGluuControllerTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @InjectMocks
    private AttestationSuperGluuController attestationSuperGluuController;

    @Mock
    private Logger log;

    @Mock
    private AttestationService attestationService;

    @Mock
    private DataMapperService dataMapperService;

    @Mock
    private Base64Service base64Service;

    @Mock
    private RawRegistrationService rawRegistrationService;

    @Mock
    private CoseService coseService;

    @Mock
    private DigestService digestService;

    @Mock
    private UserSessionIdService userSessionIdService;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Test
    void startRegistration_validValues_valid() {
        String username = "test-username";
        String appId = "test-appId";
        String sessionId = "test-sessionId";
        String enrollmentCode = "test-enrollmentCode";
        when(userSessionIdService.isValidSessionId(sessionId, username)).thenReturn(true);
        when(dataMapperService.createObjectNode()).thenReturn(mapper.createObjectNode());
        when(attestationService.options(any())).thenReturn(mapper.createObjectNode());

        JsonNode response = attestationSuperGluuController.startRegistration(username, appId, sessionId, enrollmentCode);
        assertNotNull(response);
        assertTrue(response.has("registerRequests"));
        JsonNode registerRequestsNode = response.get("registerRequests");
        assertNotNull(registerRequestsNode);
        assertFalse(registerRequestsNode.isEmpty());
        for (JsonNode itemNode : registerRequestsNode) {
            assertTrue(itemNode.has("appId"));
            assertTrue(itemNode.has("version"));
            assertEquals(itemNode.get("appId").asText(), appId);
            assertEquals(itemNode.get("version").asText(), "U2F_V2");
        }
        verify(attestationService).options(any());
        verify(dataMapperService, times(2)).createObjectNode();
    }

    @Test
    void buildFido2AttestationStartResponse_ifValidIsFalse_fido2ErrorResponseFactory() throws JsonProcessingException {
        String username = "test-username";
        String appId = "test-appId";
        String sessionId = "test-sessionId";
        when(userSessionIdService.isValidSessionId(sessionId, username)).thenReturn(false);
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> attestationSuperGluuController.buildFido2AttestationStartResponse(username, appId, sessionId));
        assertNotNull(ex);
        assertNotNull(ex.getResponse());
        assertEquals(ex.getResponse().getStatus(), 400);
        assertEquals(ex.getResponse().getEntity(), "test exception");

        verifyNoInteractions(dataMapperService, attestationService, log);
    }

    @Test
    void buildFido2AttestationStartResponse_ifOneStepIsTrue_valid() {
        String username = "";
        String appId = "test-appId";
        String sessionId = "test-sessionId";
        when(userSessionIdService.isValidSessionId(sessionId, username)).thenReturn(true);
        when(dataMapperService.createObjectNode()).thenReturn(mapper.createObjectNode());
        when(attestationService.generateUserId()).thenReturn("generate-userId");

        ObjectNode response = attestationSuperGluuController.buildFido2AttestationStartResponse(username, appId, sessionId);
        assertNotNull(response);
        assertTrue(response.has("username"));
        assertTrue(response.has("displayName"));
        assertTrue(response.has("session_id"));
        assertTrue(response.has("attestation"));
        assertTrue(response.has("super_gluu_request"));
        assertTrue(response.has("super_gluu_request_mode"));
        assertTrue(response.has("super_gluu_app_id"));
        assertEquals(response.get("username").asText(), "generate-userId");
        assertEquals(response.get("displayName").asText(), "generate-userId");
        assertEquals(response.get("session_id").asText(), sessionId);
        assertEquals(response.get("attestation").asText(), "direct");
        assertEquals(response.get("super_gluu_request").asText(), "true");
        assertEquals(response.get("super_gluu_request_mode").asText(), "one_step");
        assertEquals(response.get("super_gluu_app_id").asText(), appId);

        verify(userSessionIdService).isValidSessionId(sessionId, username);
        verify(dataMapperService).createObjectNode();
        verify(attestationService).generateUserId();
        verify(log).debug("Prepared U2F_V2 attestation options request: {}", response);
    }

    @Test
    void buildFido2AttestationStartResponse_ifOneStepIsFalse_valid() {
        String username = "test-username";
        String appId = "test-appId";
        String sessionId = "test-sessionId";
        when(userSessionIdService.isValidSessionId(sessionId, username)).thenReturn(true);
        when(dataMapperService.createObjectNode()).thenReturn(mapper.createObjectNode());

        ObjectNode response = attestationSuperGluuController.buildFido2AttestationStartResponse(username, appId, sessionId);
        assertNotNull(response);
        assertTrue(response.has("username"));
        assertTrue(response.has("displayName"));
        assertTrue(response.has("session_id"));
        assertTrue(response.has("attestation"));
        assertTrue(response.has("super_gluu_request"));
        assertTrue(response.has("super_gluu_request_mode"));
        assertTrue(response.has("super_gluu_app_id"));
        assertEquals(response.get("username").asText(), "test-username");
        assertEquals(response.get("displayName").asText(), "test-username");
        assertEquals(response.get("session_id").asText(), sessionId);
        assertEquals(response.get("attestation").asText(), "direct");
        assertEquals(response.get("super_gluu_request").asText(), "true");
        assertEquals(response.get("super_gluu_request_mode").asText(), "two_step");
        assertEquals(response.get("super_gluu_app_id").asText(), appId);

        verify(userSessionIdService).isValidSessionId(sessionId, username);
        verify(dataMapperService).createObjectNode();
        verify(attestationService, never()).generateUserId();
        verify(log).debug("Prepared U2F_V2 attestation options request: {}", response);
    }

    @Test
    void finishRegistration_validValues_valid() throws IOException {
        String username = "test_username";
        String registerResponseString = "test_response_string";
        String registrationData = "test_registration_data";
        String clientData = "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6InRlc3RfY2hhbGxlbmdlIiwib3JpZ2luIjoidGVzdF9vcmlnaW4ifQ";
        String deviceData = "test_device_data";
        RegisterResponse registerResponse = new RegisterResponse(registrationData, clientData, deviceData);
        when(dataMapperService.readValue(registerResponseString, RegisterResponse.class)).thenReturn(registerResponse);
        ObjectNode paramsNode = mapper.createObjectNode();
        ObjectNode responseNode = mapper.createObjectNode();
        ObjectNode clientDataNode = mapper.createObjectNode();
        ObjectNode attestationObjectNode = mapper.createObjectNode();
        ObjectNode attStmtNode = mapper.createObjectNode();
        when(dataMapperService.createObjectNode()).thenReturn(paramsNode, responseNode, clientDataNode, attestationObjectNode, attStmtNode);
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(
                "test_public_key".getBytes(),
                "test_key_handle".getBytes(),
                mock(X509Certificate.class),
                "test_signature".getBytes()
        );
        when(rawRegistrationService.parseRawRegisterResponse(registerResponse.getRegistrationData())).thenReturn(rawRegisterResponse);
        when(base64Service.urlEncodeToString(any())).thenReturn("test_key_handle");
        when(digestService.hashSha256(anyString())).thenReturn("test_rp_id_hash".getBytes());
        when(coseService.convertECKeyToUncompressedPoint(any())).thenReturn(mapper.createObjectNode());
        when(dataMapperService.cborWriteAsBytes(any())).thenReturn("test_cose_public_key".getBytes());
        when(attestationService.verify(any())).thenReturn(mapper.createObjectNode());

        JsonNode response = attestationSuperGluuController.finishRegistration(username, registerResponseString);
        assertNotNull(response);
        assertTrue(response.has("status"));
        assertTrue(response.has("challenge"));
        assertEquals(response.get("status").asText(), "success");
        assertEquals(response.get("challenge").asText(), "test_challenge");

        verify(attestationService).verify(paramsNode);
    }

    @Test
    void parseRegisterResponse_ifReadValueThrowException_fido2RpRuntimeException() throws IOException {
        String registerResponseString = "wrong_response_string";
        when(dataMapperService.readValue(registerResponseString, RegisterResponse.class)).thenThrow(new IOException("test_io_exception"));
        when(errorResponseFactory.invalidRequest(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> attestationSuperGluuController.parseRegisterResponse(registerResponseString));
        assertNotNull(ex);
        assertNotNull(ex.getResponse());
        assertEquals(ex.getResponse().getStatus(), 400);
        assertEquals(ex.getResponse().getEntity(), "test exception");
    }

    @Test
    void parseRegisterResponse_validValues_valid() throws IOException {
        String registerResponseString = "test_response_string";
        when(dataMapperService.readValue(registerResponseString, RegisterResponse.class)).thenReturn(mock(RegisterResponse.class));

        RegisterResponse response = attestationSuperGluuController.parseRegisterResponse(registerResponseString);
        assertNotNull(response);
    }

    @Test
    void buildFido2AttestationVerifyResponse_ifClientDataUnsupportedRegisterTypes_fido2RuntimeException() {
        String username = "test_username";
        String registrationData = "test_registration_data";
        String clientData = "eyJ0eXAiOiJ3cm9uZ190eXBlIiwiY2hhbGxlbmdlIjoidGVzdF9jaGFsbGVuZ2UiLCJvcmlnaW4iOiJ0ZXN0X29yaWdpbiJ9";
        String deviceData = "test_device_data";
        RegisterResponse registerResponse = new RegisterResponse(registrationData, clientData, deviceData);
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> attestationSuperGluuController.buildFido2AttestationVerifyResponse(username, registerResponse));
        assertNotNull(ex);
        assertNotNull(ex.getResponse());
        assertEquals(ex.getResponse().getStatus(), 400);
        assertEquals(ex.getResponse().getEntity(), "test exception");

        verifyNoInteractions(dataMapperService, base64Service, rawRegistrationService, log);
    }

    @Test
    void buildFido2AttestationVerifyResponse_ifThrowCertificateEncodingException_fido2RuntimeException() throws CertificateEncodingException, IOException {
        String username = "test_username";
        String registrationData = "test_registration_data";
        String clientData = "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6InRlc3RfY2hhbGxlbmdlIiwib3JpZ2luIjoidGVzdF9vcmlnaW4ifQ";
        String deviceData = "test_device_data";
        RegisterResponse registerResponse = new RegisterResponse(registrationData, clientData, deviceData);
        ObjectNode paramsNode = mapper.createObjectNode();
        ObjectNode responseNode = mapper.createObjectNode();
        ObjectNode clientDataNode = mapper.createObjectNode();
        ObjectNode attestationObjectNode = mapper.createObjectNode();
        ObjectNode attStmtNode = mapper.createObjectNode();
        when(dataMapperService.createObjectNode()).thenReturn(paramsNode, responseNode, clientDataNode, attestationObjectNode, attStmtNode);
        when(base64Service.urlEncodeToString(any())).thenReturn("test_client_data", "test_key_handle");
        X509Certificate x509Certificate = mock(X509Certificate.class);
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(
                "test_public_key".getBytes(),
                "test_key_handle".getBytes(),
                x509Certificate,
                "test_signature".getBytes()
        );
        when(rawRegistrationService.parseRawRegisterResponse(registerResponse.getRegistrationData())).thenReturn(rawRegisterResponse);
        when(x509Certificate.getEncoded()).thenThrow(new CertificateEncodingException("test_certificate_exception"));
        when(errorResponseFactory.invalidRequest(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> attestationSuperGluuController.buildFido2AttestationVerifyResponse(username, registerResponse));
        assertNotNull(ex);
        assertNotNull(ex.getResponse());
        assertEquals(ex.getResponse().getStatus(), 400);
        assertEquals(ex.getResponse().getEntity(), "test exception");

        verify(base64Service, times(2)).urlEncodeToString(any());
        verify(dataMapperService, never()).cborWriteAsBytes(any());
        verifyNoMoreInteractions(base64Service);
        verifyNoInteractions(log);
    }

    @Test
    void buildFido2AttestationVerifyResponse_ifThrowIOException_fido2RuntimeException() throws IOException {
        String username = "test_username";
        String registrationData = "test_registration_data";
        String clientData = "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6InRlc3RfY2hhbGxlbmdlIiwib3JpZ2luIjoidGVzdF9vcmlnaW4ifQ";
        String deviceData = "test_device_data";
        RegisterResponse registerResponse = new RegisterResponse(registrationData, clientData, deviceData);
        ObjectNode paramsNode = mapper.createObjectNode();
        ObjectNode responseNode = mapper.createObjectNode();
        ObjectNode clientDataNode = mapper.createObjectNode();
        ObjectNode attestationObjectNode = mapper.createObjectNode();
        ObjectNode attStmtNode = mapper.createObjectNode();
        when(dataMapperService.createObjectNode()).thenReturn(paramsNode, responseNode, clientDataNode, attestationObjectNode, attStmtNode);
        when(base64Service.urlEncodeToString(any())).thenReturn("test_client_data", "test_key_handle");
        when(dataMapperService.cborWriteAsBytes(any())).thenThrow(new IOException("test_io_exception"));
        when(base64Service.encodeToString(any())).thenReturn("test_attestation_certificate");
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(
                "test_public_key".getBytes(),
                "test_key_handle".getBytes(),
                mock(X509Certificate.class),
                "test_signature".getBytes()
        );
        when(rawRegistrationService.parseRawRegisterResponse(registerResponse.getRegistrationData())).thenReturn(rawRegisterResponse);
        when(errorResponseFactory.invalidRequest(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> attestationSuperGluuController.buildFido2AttestationVerifyResponse(username, registerResponse));
        assertNotNull(ex);
        assertNotNull(ex.getResponse());
        assertEquals(ex.getResponse().getStatus(), 400);
        assertEquals(ex.getResponse().getEntity(), "test exception");

        verify(base64Service, times(2)).urlEncodeToString(any());
        verify(dataMapperService).cborWriteAsBytes(any());
        verifyNoMoreInteractions(base64Service);
        verifyNoInteractions(log);
    }

    @Test
    void buildFido2AttestationVerifyResponse_validValues_valid() throws IOException {
        String username = "test_username";
        String registrationData = "test_registration_data";
        String clientData = "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6InRlc3RfY2hhbGxlbmdlIiwib3JpZ2luIjoidGVzdF9vcmlnaW4ifQ";
        String deviceData = "test_device_data";
        RegisterResponse registerResponse = new RegisterResponse(registrationData, clientData, deviceData);
        ObjectNode paramsNode = mapper.createObjectNode();
        ObjectNode responseNode = mapper.createObjectNode();
        ObjectNode clientDataNode = mapper.createObjectNode();
        ObjectNode attestationObjectNode = mapper.createObjectNode();
        ObjectNode attStmtNode = mapper.createObjectNode();
        when(dataMapperService.createObjectNode()).thenReturn(paramsNode, responseNode, clientDataNode, attestationObjectNode, attStmtNode);
        when(base64Service.urlEncodeToString(any())).thenReturn("test_client_data", "test_key_handle");
        when(dataMapperService.cborWriteAsBytes(any())).thenReturn("test_code_public_key".getBytes(), "test_attestation_object".getBytes());
        when(base64Service.encodeToString(any())).thenReturn("test_attestation_certificate");
        RawRegisterResponse rawRegisterResponse = new RawRegisterResponse(
                "test_public_key".getBytes(),
                "test_key_handle".getBytes(),
                mock(X509Certificate.class),
                "test_signature".getBytes()
        );
        when(rawRegistrationService.parseRawRegisterResponse(registerResponse.getRegistrationData())).thenReturn(rawRegisterResponse);
        when(digestService.hashSha256(anyString())).thenReturn("test_rp_id_hash".getBytes());
        when(coseService.convertECKeyToUncompressedPoint(any())).thenReturn(mapper.createObjectNode());

        ObjectNode response = attestationSuperGluuController.buildFido2AttestationVerifyResponse(username, registerResponse);
        assertNotNull(response);
        assertTrue(response.has("super_gluu_request"));
        assertTrue(response.has("super_gluu_request_mode"));
        assertTrue(response.has("super_gluu_request_cancel"));
        assertTrue(response.has("id"));
        assertTrue(response.has("type"));
        assertTrue(response.has("response"));
        assertEquals(response.get("super_gluu_request").asText(), "true");
        assertEquals(response.get("super_gluu_request_mode").asText(), "two_step");
        assertEquals(response.get("super_gluu_request_cancel").asText(), "false");
        assertEquals(response.get("id").asText(), "test_key_handle");
        assertEquals(response.get("type").asText(), "public-key");
        JsonNode response1Node = response.get("response");
        assertTrue(response1Node.has("deviceData"));
        assertTrue(response1Node.has("clientDataJSON"));
        assertTrue(response1Node.has("attestationObject"));
        assertEquals(response1Node.get("deviceData").asText(), "test_device_data");
        assertEquals(response1Node.get("clientDataJSON").asText(), "test_client_data");
        assertEquals(response1Node.get("attestationObject").asText(), "test_key_handle");

        verify(dataMapperService, times(5)).createObjectNode();
        verify(dataMapperService, times(2)).cborWriteAsBytes(any());
        verify(base64Service, times(3)).urlEncodeToString(any());
        verify(base64Service).encodeToString(any());
        verify(log).debug("Prepared U2F_V2 attestation verify request: {}", response);
        verify(rawRegistrationService).parseRawRegisterResponse(any());
    }
}
