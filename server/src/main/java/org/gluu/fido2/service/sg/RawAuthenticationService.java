package org.gluu.fido2.service.sg;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;

import io.jans.as.model.fido.u2f.exception.BadInputException;
import io.jans.as.model.fido.u2f.message.RawAuthenticateResponse;
import io.jans.as.model.util.Base64Util;
import io.jans.util.io.ByteDataInputStream;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
/**
 * Provides operations with U2F RAW registration response
 *
 * @author Yuriy Movchan Date: 05/20/2015
 */
@ApplicationScoped
public class RawAuthenticationService {

	public static final String AUTHENTICATE_GET_TYPE = "navigator.id.getAssertion";
	public static final String AUTHENTICATE_CANCEL_TYPE = "navigator.id.cancelAssertion";
	public static final String[] SUPPORTED_AUTHENTICATE_TYPES = new String[] { AUTHENTICATE_GET_TYPE, AUTHENTICATE_CANCEL_TYPE };

	@Inject
	private Logger log;

	public RawAuthenticateResponse parseRawAuthenticateResponse(String rawDataBase64) {
		ByteDataInputStream bis = new ByteDataInputStream(Base64Util.base64urldecode(rawDataBase64));
		try {
			return new RawAuthenticateResponse(bis.readSigned(), bis.readInt(), bis.readAll());
		} catch (IOException ex) {
			throw new BadInputException("Failed to parse RAW authenticate response", ex);
		} finally {
			IOUtils.closeQuietly(bis);
		}
	}

}
