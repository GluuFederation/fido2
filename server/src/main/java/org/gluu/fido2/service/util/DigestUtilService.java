package org.gluu.fido2.service.util;

import javax.enterprise.context.ApplicationScoped;

import org.apache.commons.codec.digest.DigestUtils;

@ApplicationScoped
public class DigestUtilService {

    public byte[] sha256Digest(byte[] input) {
        return DigestUtils.getSha256Digest().digest(input);
    }
}
