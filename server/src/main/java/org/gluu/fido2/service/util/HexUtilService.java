package org.gluu.fido2.service.util;

import javax.enterprise.context.ApplicationScoped;

import org.apache.commons.codec.binary.Hex;

@ApplicationScoped
public class HexUtilService {

    public String encodeHexString(byte[] input) {
        return Hex.encodeHexString(input);
    }
}
