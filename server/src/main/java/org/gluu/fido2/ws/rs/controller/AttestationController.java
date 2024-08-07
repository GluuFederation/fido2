/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Gluu
 */

package org.gluu.fido2.ws.rs.controller;

import java.io.IOException;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.DataMapperService;
import org.gluu.fido2.service.operation.AttestationService;
import org.gluu.fido2.service.sg.converter.AttestationSuperGluuController;
import org.gluu.fido2.service.verifier.CommonVerifiers;
import org.slf4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * serves request for /attestation endpoint exposed by FIDO2 sever
 *
 * @author Yuriy Movchan
 * @version May 08, 2020
 */
@ApplicationScoped
@Path("/attestation")
public class AttestationController {

    @Inject
    private Logger log;

    @Inject
    private AttestationService attestationService;

    @Inject
    private DataMapperService dataMapperService;

    @Inject
    private CommonVerifiers commonVerifiers;

    @Inject
    private AttestationSuperGluuController attestationSuperGluuController;

    @Inject
    private AppConfiguration appConfiguration;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    @POST
    @Consumes({"application/json"})
    @Produces({"application/json"})
    @Path("/options")
    public Response register(String content) {
        try {
            if (appConfiguration.getFido2Configuration() == null) {
                throw errorResponseFactory.forbiddenException();
            }

            JsonNode params;
            try {
                params = dataMapperService.readTree(content);
            } catch (IOException ex) {
                throw errorResponseFactory.invalidRequest(ex.getMessage(), ex);
            }

            commonVerifiers.verifyNotUseGluuParameters(params);
            JsonNode result = attestationService.options(params);

            ResponseBuilder builder = Response.ok().entity(result.toString());
            return builder.build();

        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unknown Error: {}", e.getMessage(), e);
            throw errorResponseFactory.unknownError(e.getMessage());
        }
    }

    @POST
    @Consumes({"application/json"})
    @Produces({"application/json"})
    @Path("/result")
    public Response verify(String content) {
        try {
            if (appConfiguration.getFido2Configuration() == null) {
                throw errorResponseFactory.forbiddenException();
            }

            JsonNode params;
            try {
                params = dataMapperService.readTree(content);
            } catch (IOException ex) {
                throw errorResponseFactory.invalidRequest(ex.getMessage(), ex);
            }

            commonVerifiers.verifyNotUseGluuParameters(params);
            JsonNode result = attestationService.verify(params);

            ResponseBuilder builder = Response.ok().entity(result.toString());
            return builder.build();

        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unknown Error: {}", e.getMessage(), e);
            throw errorResponseFactory.unknownError(e.getMessage());
        }
    }

    @GET
    @Produces({"application/json"})
    @Path("/registration")
    public Response startRegistration(@QueryParam("username") String userName, @QueryParam("application") String appId, @QueryParam("session_id") String sessionId, @QueryParam("enrollment_code") String enrollmentCode) {
        try {
            if ((appConfiguration.getFido2Configuration() == null) && !appConfiguration.isSuperGluuEnabled()) {
                throw errorResponseFactory.forbiddenException();
            }

            log.debug("Start registration: username = {}, application = {}, session_id = {}, enrollment_code = {}", userName, appId, sessionId, enrollmentCode);

            JsonNode result = attestationSuperGluuController.startRegistration(userName, appId, sessionId, enrollmentCode);

            log.debug("Prepared U2F_V2 registration options request: {}", result.toString());

            ResponseBuilder builder = Response.ok().entity(result.toString());
            return builder.build();

        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unknown Error: {}", e.getMessage(), e);
            throw errorResponseFactory.unknownError(e.getMessage());
        }
    }

    @POST
    @Produces({"application/json"})
    @Path("/registration")
    public Response finishRegistration(@FormParam("username") String userName, @FormParam("tokenResponse") String registerResponseString) {
        try {
            if ((appConfiguration.getFido2Configuration() == null) && !appConfiguration.isSuperGluuEnabled()) {
                throw errorResponseFactory.forbiddenException();
            }

            log.debug("Finish registration: username = {}, tokenResponse = {}", userName, registerResponseString);

            JsonNode result = attestationSuperGluuController.finishRegistration(userName, registerResponseString);

            log.debug("Prepared U2F_V2 registration verify request: {}", result.toString());

            ResponseBuilder builder = Response.ok().entity(result.toString());
            return builder.build();

        } catch (WebApplicationException e) {
            throw e;
        } catch (Exception e) {
            log.error("Unknown Error: {}", e.getMessage(), e);
            throw errorResponseFactory.unknownError(e.getMessage());
        }
    }
}
