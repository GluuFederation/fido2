/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.gluu.fido2.service.shared;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.model.ApplicationType;

/**
 * Obtain Organization Info
 *
 */
@ApplicationScoped
public class OrganizationService extends org.gluu.service.OrganizationService {

	@Inject
	private AppConfiguration appConfiguration;

    protected boolean isUseLocalCache() {
    	return appConfiguration.isUseLocalCache();
    }

	@Override
	public ApplicationType getApplicationType() {
		return ApplicationType.FIDO2;
	}

}