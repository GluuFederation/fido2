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
import javax.ws.rs.core.Response.Status;

import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.service.DataMapperService;

import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * The endpoint at which the requester can obtain FIDO2 metadata
 * configuration
 *
 * @author Yuriy Movchan Date: 12/19/2018
 */
@ApplicationScoped
@Path("/fido2/configuration")
public class ConfigurationController {

	@Inject
	private AppConfiguration appConfiguration;

    @Inject
    private DataMapperService dataMapperService;

	@GET
	@Produces({ "application/json" })
	public Response getConfiguration() {
        if (appConfiguration.getFido2Configuration() == null) {
            return Response.status(Status.FORBIDDEN).build();
        }

	    final String baseEndpointUri = appConfiguration.getBaseEndpoint();
	    ObjectNode response = dataMapperService.createObjectNode();
        
        response.put("version", "1.1");
        response.put("issuer", appConfiguration.getIssuer());

        ObjectNode attestation = dataMapperService.createObjectNode();
        response.set("attestation", attestation);
        attestation.put("base_path", baseEndpointUri + "/fido2/attestation");
        attestation.put("options_enpoint", baseEndpointUri + "/fido2/attestation/options");
        attestation.put("result_enpoint", baseEndpointUri + "/fido2/attestation/result");

        ObjectNode assertion = dataMapperService.createObjectNode();
        response.set("assertion", assertion);
        assertion.put("base_path", baseEndpointUri + "/fido2/assertion");
        assertion.put("options_enpoint", baseEndpointUri + "/fido2/assertion/options");
        assertion.put("result_enpoint", baseEndpointUri + "/fido2/assertion/result");

        ResponseBuilder builder = Response.ok().entity(response.toString());
        return builder.build();
	}

}
