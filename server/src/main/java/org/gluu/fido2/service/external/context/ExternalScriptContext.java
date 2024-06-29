package org.gluu.fido2.service.external.context;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.jboss.resteasy.spi.NoLogWebApplicationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExternalScriptContext {

    private static final Logger log = LoggerFactory.getLogger(ExternalScriptContext.class);

    private NoLogWebApplicationException webApplicationException;

    private final Map<String, Object> contextVariables;

    protected HttpServletRequest httpRequest;
    protected final HttpServletResponse httpResponse;

    public ExternalScriptContext(HttpServletRequest httpRequest) {
        this(httpRequest, null);
    }

    public ExternalScriptContext(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        this.contextVariables = new HashMap();
        this.httpRequest = httpRequest;
        this.httpResponse = httpResponse;
    }

    public Logger getLog() {
        return log;
    }

    public HttpServletRequest getHttpRequest() {
        return httpRequest;
    }

    public HttpServletResponse getHttpResponse() {
        return httpResponse;
    }

    public String getIpAddress() {
        return httpRequest != null ? httpRequest.getRemoteAddr() : "";
    }

    public Map<String, Object> getContextVariables() {
        return contextVariables;
    }

    public NoLogWebApplicationException getWebApplicationException() {
        return webApplicationException;
    }

    public void setWebApplicationException(NoLogWebApplicationException webApplicationException) {
        this.webApplicationException = webApplicationException;
    }

    public NoLogWebApplicationException createWebApplicationException(Response response) {
        return new NoLogWebApplicationException(response);
    }

    public NoLogWebApplicationException createWebApplicationException(int status, String entity) {
        this.webApplicationException = new NoLogWebApplicationException(Response
                .status(status)
                .entity(entity)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build());
        return this.webApplicationException;
    }

    public void throwWebApplicationExceptionIfSet() {
        if (webApplicationException != null)
            throw webApplicationException;
    }
}
