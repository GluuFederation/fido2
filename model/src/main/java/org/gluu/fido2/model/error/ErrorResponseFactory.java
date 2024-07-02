package org.gluu.fido2.model.error;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.NOT_FOUND;

import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang.BooleanUtils;
import org.apache.logging.log4j.ThreadContext;
import org.gluu.fido2.model.assertion.AssertionErrorResponseType;
import org.gluu.fido2.model.attestation.AttestationErrorResponseType;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.model.error.ErrorMessage;
import org.gluu.oxauth.model.configuration.Configuration;
import org.gluu.oxauth.model.error.DefaultErrorResponse;
import org.gluu.oxauth.model.error.IErrorType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ErrorResponseFactory implements Configuration {

    private static final Logger log = LoggerFactory.getLogger(ErrorResponseFactory.class);

    public static final String CORRELATION_ID_HEADER = "X-Correlation-Id";

    private Fido2ErrorMessages messages;

    private AppConfiguration appConfiguration;

    public ErrorResponseFactory() {
    }

    public ErrorResponseFactory(Fido2ErrorMessages messages, AppConfiguration appConfiguration) {
        this.messages = messages;
        this.appConfiguration = appConfiguration;
    }

    public WebApplicationException createWebApplicationException(Response.Status status, IErrorType type, String reason) {
        return createWebApplicationException(status, type, reason, null);
    }

    private WebApplicationException createWebApplicationException(Response.Status status, IErrorType type, String reason, Throwable e) {
        WebApplicationException error = new WebApplicationException(Response
                .status(status)
                .entity(errorAsJson(type, reason))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build());
        if (log.isErrorEnabled()) {
            log.error("Exception Handle, status: {}, body: {}", formatStatus(error.getResponse().getStatusInfo()), error.getResponse().getEntity(), e);
        }
        return error;
    }

    public WebApplicationException badRequestException(IErrorType type, String reason) {
        return createWebApplicationException(BAD_REQUEST, type, reason);
    }

    public WebApplicationException badRequestException(IErrorType type, String reason, Throwable e) {
        return createWebApplicationException(BAD_REQUEST, type, reason, e);
    }

    public WebApplicationException notFoundException(IErrorType type, String reason) {
        return createWebApplicationException(NOT_FOUND, type, reason);
    }

    public WebApplicationException forbiddenException() {
        WebApplicationException error = new WebApplicationException(Response
                .status(FORBIDDEN)
                .entity("")
                .build());
        if (log.isErrorEnabled()) {
            log.error("Exception Handle, status: {}", formatStatus(error.getResponse().getStatusInfo()));
        }
        return error;
    }

    public WebApplicationException invalidRequest(String reason) {
        return createWebApplicationException(BAD_REQUEST, CommonErrorResponseType.INVALID_REQUEST, reason);
    }

    public WebApplicationException invalidRequest(String reason, Throwable e) {
        return createWebApplicationException(BAD_REQUEST, CommonErrorResponseType.INVALID_REQUEST, reason, e);
    }

    public WebApplicationException unknownError(String reason) {
        throw createWebApplicationException(INTERNAL_SERVER_ERROR, CommonErrorResponseType.UNKNOWN_ERROR, reason);
    }

    private String errorAsJson(IErrorType type, String reason) {
        final DefaultErrorResponse error = getErrorResponse(type);
        error.setReason(BooleanUtils.isTrue(appConfiguration.getErrorReasonEnabled()) ? reason : "");
        return error.toJSonString();
    }

    private DefaultErrorResponse getErrorResponse(IErrorType type) {
        final DefaultErrorResponse response = new DefaultErrorResponse();
        response.setType(type);
        if (type != null && messages != null) {
            List<ErrorMessage> list = null;
            if (type instanceof CommonErrorResponseType) {
                list = messages.getCommon();
            } else if (type instanceof AssertionErrorResponseType) {
                list = messages.getAssertion();
            } else if (type instanceof AttestationErrorResponseType) {
                list = messages.getAttestation();
            }
            if (list != null) {
                final ErrorMessage m = getError(list, type);
                String description = Optional.ofNullable(ThreadContext.get(CORRELATION_ID_HEADER))
                        .map(id -> m.getDescription().concat(" CorrelationId: " + id))
                        .orElse(m.getDescription());
                response.setErrorDescription(description);
                response.setErrorUri(m.getUri());
            }
        }

        return response;
    }

    /**
     * Looks for an error message.
     *
     * @param list error list
     * @param type The type of the error.
     * @return Error message or <code>null</code> if not found.
     */
    private ErrorMessage getError(List<ErrorMessage> list, IErrorType type) {
        log.debug("Looking for the error with id: {}", type);

        if (list != null) {
            Predicate<ErrorMessage> equalsErrorMessageId = s -> s.getId().equals(type.getParameter());
            Optional<ErrorMessage> errorMessage = list.stream().filter(equalsErrorMessageId).findFirst();
            if (errorMessage.isPresent()) {
                log.debug("Found error, id: {}", type);
                return errorMessage.get();
            }
        }

        log.error("Error not found, id: {}", type);
        return new ErrorMessage(type.getParameter(), type.getParameter(), null);
    }

    private String formatStatus(Response.StatusType status) {
        return String.format("%s %s", status.getStatusCode(), status);
    }
}
