package org.gluu.fido2.model.error;

import java.util.List;

import org.gluu.model.error.ErrorMessage;
import org.gluu.oxauth.model.configuration.Configuration;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "errors")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Fido2ErrorMessages implements Configuration {

    @XmlElementWrapper(name = "common")
    @XmlElement(name = "error")
    private List<ErrorMessage> common;

    @XmlElementWrapper(name = "assertion")
    @XmlElement(name = "error")
    private List<ErrorMessage> assertion;

    @XmlElementWrapper(name = "attestation")
    @XmlElement(name = "error")
    private List<ErrorMessage> attestation;

    public List<ErrorMessage> getCommon() {
        return common;
    }

    public void setCommon(List<ErrorMessage> common) {
        this.common = common;
    }

    public List<ErrorMessage> getAssertion() {
        return assertion;
    }

    public void setAssertion(List<ErrorMessage> assertion) {
        this.assertion = assertion;
    }

    public List<ErrorMessage> getAttestation() {
        return attestation;
    }

    public void setAttestation(List<ErrorMessage> attestation) {
        this.attestation = attestation;
    }
}
