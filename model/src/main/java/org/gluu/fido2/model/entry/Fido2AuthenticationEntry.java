/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2020, Gluu
 */

package org.gluu.fido2.model.entry;

import java.io.Serializable;
import java.util.Date;

import org.gluu.persist.annotation.AttributeName;
import org.gluu.persist.annotation.JsonObject;
import org.gluu.persist.annotation.ObjectClass;

/**
 * Fido2 registration entry
 *
 * @author Yuriy Movchan
 * @version 11/02/2018
 */
@ObjectClass(value = "oxFido2AuthenticationEntry")
public class Fido2AuthenticationEntry extends Fido2Entry implements Serializable {

    private static final long serialVersionUID = -2242931562244920584L;

    @JsonObject
    @AttributeName(name = "oxAuthenticationData")
    private Fido2AuthenticationData authenticationData;

    @JsonObject
    @AttributeName(name = "oxStatus")
    private Fido2AuthenticationStatus authenticationStatus;

    @AttributeName(name = "oxCodeChallengeHash")
    private String challangeHash;

    public Fido2AuthenticationEntry() {
    }

    public Fido2AuthenticationEntry(String dn, String id, Date creationDate, String userInum, Fido2AuthenticationData authenticationData) {
        super(dn, id, creationDate, userInum, authenticationData.getChallenge());
        this.authenticationData = authenticationData;
    }

    public Fido2AuthenticationData getAuthenticationData() {
        return authenticationData;
    }

    public void setAuthenticationData(Fido2AuthenticationData authenticationData) {
        this.authenticationData = authenticationData;
    }

    public Fido2AuthenticationStatus getAuthenticationStatus() {
        return authenticationStatus;
    }

    public void setAuthenticationStatus(Fido2AuthenticationStatus authenticationStatus) {
        this.authenticationStatus = authenticationStatus;
    }

    public String getChallangeHash() {
        return challangeHash;
    }

    public void setChallangeHash(String challangeHash) {
        this.challangeHash = challangeHash;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Fido2AuthenticationEntry [authenticationData=").append(authenticationData).append("]");
        return builder.toString();
    }
}
