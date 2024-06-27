package org.gluu.fido2.service;

/**
 * Method to calculate digests
 *
 */
@ApplicationScoped
public class DigestService {

    public byte[] hashSha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] hashSha256(String str) {
        return hashSha256(str.getBytes());
    }

}
