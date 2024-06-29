package org.gluu.fido2.service.external.context;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.gluu.model.custom.script.conf.CustomScriptConfiguration;
import org.gluu.persist.model.fido2.Fido2AuthenticationEntry;
import org.gluu.persist.model.fido2.Fido2RegistrationEntry;

import com.fasterxml.jackson.databind.JsonNode;

public class ExternalFido2Context extends org.gluu.fido2.service.external.context.ExternalScriptContext {

    private final JsonNode jsonNode;
    private CustomScriptConfiguration script;

    private final HashMap<String, Object> paremeters;
	private Fido2RegistrationEntry registrationEntry;
	private Fido2AuthenticationEntry authenticationEntity;

    public ExternalFido2Context(JsonNode jsonNode, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        super(httpRequest, httpResponse);
        this.jsonNode = jsonNode;
        this.paremeters = new HashMap<>();
    }

    public CustomScriptConfiguration getScript() {
        return script;
    }

    public void setScript(CustomScriptConfiguration script) {
        this.script = script;
    }

    public JsonNode getJsonNode() {
        return jsonNode;
    }
    
    public HashMap<String, Object> getParemeters() {
		return paremeters;
	}

	public void addToContext(Fido2RegistrationEntry registrationEntry, Fido2AuthenticationEntry authenticationEntity) {
		this.registrationEntry = registrationEntry;
		this.authenticationEntity = authenticationEntity;
	}

	public Fido2RegistrationEntry getRegistrationEntry() {
		return registrationEntry;
	}

	public Fido2AuthenticationEntry getAuthenticationEntity() {
		return authenticationEntity;
	}

	@Override
	public String toString() {
		return "ExternalFido2Context [jsonNode=" + jsonNode + ", script=" + script + ", paremeters="
				+ paremeters + "]";
	}

}
