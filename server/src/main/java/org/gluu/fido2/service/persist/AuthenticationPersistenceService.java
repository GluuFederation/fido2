/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Gluu
 */

package org.gluu.fido2.service.persist;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.apache.commons.lang3.StringUtils;
import org.gluu.fido2.model.attestation.AttestationErrorResponseType;
import org.gluu.fido2.model.conf.AppConfiguration;
import org.gluu.fido2.model.error.ErrorResponseFactory;
import org.gluu.fido2.service.ChallengeGenerator;
import org.gluu.fido2.service.shared.UserService;
import org.gluu.oxauth.model.common.User;
import org.gluu.oxauth.model.config.StaticConfiguration;
import org.gluu.persist.PersistenceEntryManager;
import org.gluu.persist.model.base.SimpleBranch;
import org.gluu.persist.model.fido2.Fido2AuthenticationData;
import org.gluu.persist.model.fido2.Fido2AuthenticationEntry;
import org.gluu.search.filter.Filter;
import org.gluu.util.StringHelper;
import org.slf4j.Logger;

/**
 * Every authentication is persisted under Person Entry
 * 
 * @author Yuriy Movchan
 * @version May 08, 2020
 */
@ApplicationScoped
public class AuthenticationPersistenceService {

    @Inject
    private Logger log;

    @Inject
    private StaticConfiguration staticConfiguration;

    @Inject
    private AppConfiguration appConfiguration;

	@Inject
	private ChallengeGenerator challengeGenerator;

    @Inject
    private UserService userService;

    @Inject
    private PersistenceEntryManager persistenceEntryManager;

    @Inject
    private ErrorResponseFactory errorResponseFactory;

    public void save(Fido2AuthenticationData authenticationData) {
        Fido2AuthenticationEntry authenticationEntity = buildFido2AuthenticationEntry(authenticationData, false);

        save(authenticationEntity);
    }

    public void save(Fido2AuthenticationEntry authenticationEntity) {
        prepareBranch(authenticationEntity.getUserInum());

        persistenceEntryManager.persist(authenticationEntity);
    }

    public Fido2AuthenticationEntry buildFido2AuthenticationEntry(Fido2AuthenticationData authenticationData, boolean oneStep) {
		String userName = authenticationData.getUsername();
        
		String userInum = null;
    	if (!oneStep) {
	        User user = userService.getUser(userName, "inum");
	        if (user == null) {
	            if (appConfiguration.getFido2Configuration().isUserAutoEnrollment()) {
	                user = userService.addDefaultUser(userName);
	            } else {
	                throw errorResponseFactory.badRequestException(AttestationErrorResponseType.USER_AUTO_ENROLLMENT_IS_DISABLED, "Auto user enrollment was disabled. User not exists!");
	            }
	        }
	        userInum = userService.getUserInum(user);
    	}

        Date now = new GregorianCalendar(TimeZone.getTimeZone("UTC")).getTime();
        final String id = UUID.randomUUID().toString();
        final String challenge = authenticationData.getChallenge();

        String dn = oneStep ? getDnForAuthenticationEntry(null, id) : getDnForAuthenticationEntry(userInum, id);
        Fido2AuthenticationEntry authenticationEntity = new Fido2AuthenticationEntry(dn, authenticationData.getId(), now, userInum, authenticationData);
        authenticationEntity.setAuthenticationStatus(authenticationData.getStatus());
        if (StringUtils.isNotEmpty(challenge)) {
        	authenticationEntity.setChallengeHash(challengeGenerator.getChallengeHashCode(challenge));
        }
        authenticationEntity.setRpId(authenticationData.getApplicationId());

        authenticationData.setCreatedDate(now);
        authenticationData.setCreatedBy(userName);

        return authenticationEntity;
	}

    public void update(Fido2AuthenticationEntry authenticationEntity) {
        Date now = new GregorianCalendar(TimeZone.getTimeZone("UTC")).getTime();

        Fido2AuthenticationData authenticationData = authenticationEntity.getAuthenticationData();
        authenticationData.setUpdatedDate(now);
        authenticationData.setUpdatedBy(authenticationData.getUsername());

        authenticationEntity.setAuthenticationStatus(authenticationData.getStatus());

        persistenceEntryManager.merge(authenticationEntity);
    }

    public void addBranch(final String baseDn) {
        SimpleBranch branch = new SimpleBranch();
        branch.setOrganizationalUnitName("fido2_auth");
        branch.setDn(baseDn);

        persistenceEntryManager.persist(branch);
    }

    public boolean containsBranch(final String baseDn) {
        return persistenceEntryManager.contains(baseDn, SimpleBranch.class);
    }

    public void prepareBranch(final String userInum) {
        String baseDn = getBaseDnForFido2AuthenticationEntries(userInum);
        if (!persistenceEntryManager.hasBranchesSupport(baseDn)) {
        	return;
        }

        // Create Fido2 base branch for authentication entries if needed
        if (!containsBranch(baseDn)) {
            addBranch(baseDn);
        }
    }

    public List<Fido2AuthenticationEntry> findByChallenge(String challenge, boolean oneStep) {
        String baseDn = oneStep ? getDnForAuthenticationEntry(null, null) : getBaseDnForFido2AuthenticationEntries(null);

        Filter codeChallengFilter = Filter.createEqualityFilter("oxCodeChallenge", challenge);
        Filter codeChallengHashCodeFilter = Filter.createEqualityFilter("oxCodeChallengeHash", challengeGenerator.getChallengeHashCode(challenge));
        Filter filter = Filter.createANDFilter(codeChallengFilter, codeChallengHashCodeFilter);

        List<Fido2AuthenticationEntry> fido2AuthenticationEntries = persistenceEntryManager.findEntries(baseDn, Fido2AuthenticationEntry.class, filter);

        return fido2AuthenticationEntries;
    }

    public String getDnForAuthenticationEntry(String userInum, String jsId) {
    	String baseDn;
    	if (StringHelper.isEmpty(userInum)) {
    		baseDn = staticConfiguration.getBaseDn().getFido2Assertion();
    	} else {
	        // Build DN string for Fido2 registration entry
	        baseDn = getBaseDnForFido2AuthenticationEntries(userInum);
    	}
        // Build DN string for Fido2 authentication entry
        if (StringHelper.isEmpty(jsId)) {
            return baseDn;
        }
        return String.format("oxId=%s,%s", jsId, baseDn);
    }

    public String getBaseDnForFido2AuthenticationEntries(String userInum) {
        final String userBaseDn = getDnForUser(userInum); // "ou=fido2_auth,inum=1234,ou=people,o=gluu"
        if (StringHelper.isEmpty(userInum)) {
            return userBaseDn;
        }

        return String.format("ou=fido2_auth,%s", userBaseDn);
    }

    public String getDnForUser(String userInum) {
        String peopleDn = staticConfiguration.getBaseDn().getPeople();
        if (StringHelper.isEmpty(userInum)) {
            return peopleDn;
        }

        return String.format("inum=%s,%s", userInum, peopleDn);
    }

}
