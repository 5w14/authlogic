package net.fivew14.authlogic.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Provides hashing functions for authentication system.
 */
public class Hasher {

    /**
     * Computes SHA-256 hash of input data.
     *
     * @param data Input bytes to hash
     * @return SHA-256 digest (32 bytes)
     * @throws RuntimeException if SHA-256 is not available
     */
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Computes SHA-256 hash of a string (UTF-8 encoded).
     *
     * @param data Input string to hash
     * @return SHA-256 digest (32 bytes)
     */
    public static byte[] sha256(String data) {
        return sha256(data.getBytes(StandardCharsets.UTF_8));
    }
}
