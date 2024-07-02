/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Gluu
 */

package org.gluu.fido2.ws.rs.controller;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.DataMapperService;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The endpoint at which the requester can obtain FIDO2 metadata
 * configuration
 *
 * @author Yuriy Movchan Date: 12/19/2018
 */
@ApplicationScoped
@Path("/configuration")
public class ConfigurationController {

	@Inject
	private AppConfiguration appConfiguration;

    @Inject
    private DataMapperService dataMapperService;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

	@GET
	@Produces({ "application/json" })
	public Response getConfiguration() {
        if (appConfiguration.getFido2Configuration() == null) {
            throw errorResponseFactory.forbiddenException();
        }

	    final String baseEndpointUri = appConfiguration.getBaseEndpoint();
	    ObjectNode response = dataMapperService.createObjectNode();
        
        response.put("version", "1.1");
        response.put("issuer", appConfiguration.getIssuer());

        ObjectNode attestation = dataMapperService.createObjectNode();
        response.set("attestation", attestation);
        attestation.put("base_path", baseEndpointUri + "/attestation");
        attestation.put("options_endpoint", baseEndpointUri + "/attestation/options");
        attestation.put("result_endpoint", baseEndpointUri + "/attestation/result");

        ObjectNode assertion = dataMapperService.createObjectNode();
        response.set("assertion", assertion);
        assertion.put("base_path", baseEndpointUri + "/assertion");
        assertion.put("options_endpoint", baseEndpointUri + "/assertion/options");
        if (appConfiguration.getFido2Configuration().isAssertionOptionsGenerateEndpointEnabled()) {
            assertion.put("options_generate_endpoint", baseEndpointUri + "/assertion/options/generate");
        }
        assertion.put("result_endpoint", baseEndpointUri + "/assertion/result");

        if (appConfiguration.isSuperGluuEnabled()) {
        	response.put("super_gluu_registration_endpoint", baseEndpointUri + "/attestation/registration");
        	response.put("super_gluu_authentication_endpoint", baseEndpointUri + "/assertion/authentication");
        }

        ResponseBuilder builder = Response.ok().entity(response.toString());
        return builder.build();
	}

}
