package org.gluu.fido2.service.verifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

@ExtendWith(MockitoExtension.class)
class DomainVerifierTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @InjectMocks
    private DomainVerifier domainVerifier;

    @Mock
    private Logger log;

    @Mock
    private CommonVerifiers commonVerifiers;

    @Mock
    private ErrorResponseFactory errorResponseFactory;

    @Test
    void verifyDomain_valid_true() {
        String domain = "test.url";
        String originKey = "origin";
        String originValue = "https://test.url";
        ObjectNode clientDataNode = mapper.createObjectNode();
        clientDataNode.put(originKey, domain);
        when(commonVerifiers.verifyThatFieldString(clientDataNode, originKey)).thenReturn(originValue);

        boolean result = domainVerifier.verifyDomain(domain, clientDataNode);
        assertTrue(result);
        verify(log).debug("Domains comparison {} {}", domain, originValue);
        verifyNoMoreInteractions(log);
    }

    @Test
    void verifyDomain_originNotHost_true() {
        String domain = "test.url";
        String originKey = "origin";
        String originValue = "test.url";
        ObjectNode clientDataNode = mapper.createObjectNode();
        clientDataNode.put(originKey, domain);
        when(commonVerifiers.verifyThatFieldString(clientDataNode, originKey)).thenReturn(originValue);

        boolean result = domainVerifier.verifyDomain(domain, clientDataNode);
        assertTrue(result);
        verify(log).debug("Domains comparison {} {}", domain, originValue);
        verify(log).warn(contains("MalformedURLException"), anyString());
    }

    @Test
    void verifyDomain_domainNotEquals_true() {
        String domain = "testurl";
        String originKey = "origin";
        String originValue = "https://test1.testurl";
        ObjectNode clientDataNode = mapper.createObjectNode();
        clientDataNode.put(originKey, domain);
        when(commonVerifiers.verifyThatFieldString(clientDataNode, originKey)).thenReturn(originValue);

        boolean result = domainVerifier.verifyDomain(domain, clientDataNode);
        assertTrue(result);
        verify(log).debug("Domains comparison {} {}", domain, originValue);
        verifyNoMoreInteractions(log);
    }

    @Test
    void verifyDomain_effectiveDomainNotEndWith_fido2RpRuntimeException() {
        String domain = "test.url";
        String originKey = "origin";
        String originValue = "https://test1.url";
        ObjectNode clientDataNode = mapper.createObjectNode();
        clientDataNode.put(originKey, domain);
        when(commonVerifiers.verifyThatFieldString(clientDataNode, originKey)).thenReturn(originValue);
        when(errorResponseFactory.badRequestException(any(), any())).thenReturn(new WebApplicationException(Response.status(400).entity("test exception").build()));

        WebApplicationException ex = assertThrows(WebApplicationException.class, () -> domainVerifier.verifyDomain(domain, clientDataNode));
        assertNotNull(ex);
        assertNotNull(ex.getResponse());
        assertEquals(ex.getResponse().getStatus(), 400);
        assertEquals(ex.getResponse().getEntity(), "test exception");

        verify(log).debug("Domains comparison {} {}", domain, originValue);
        verifyNoMoreInteractions(log);
    }
}
