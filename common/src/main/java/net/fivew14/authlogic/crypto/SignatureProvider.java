package net.fivew14.authlogic.crypto;

import java.security.*;

/**
 * Provides RSA signature generation and verification for authentication protocol.
 * Uses SHA256withRSA for all signing operations.
 */
public class SignatureProvider {
    private static final String ALGORITHM = "SHA256withRSA";

    /**
     * Signs concatenated byte components with the given private key.
     *
     * @param privateKey RSA private key
     * @param components Byte arrays to concatenate and sign
     * @return Signature bytes
     * @throws RuntimeException if signing fails
     */
    public static byte[] sign(PrivateKey privateKey, byte[]... components) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initSign(privateKey);

            // Sign all components in order
            for (byte[] component : components) {
                signature.update(component);
            }

            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Failed to sign data", e);
        }
    }

    /**
     * Verifies a signature against concatenated byte components.
     *
     * @param publicKey      RSA public key
     * @param signatureBytes The signature to verify
     * @param components     Byte arrays to concatenate and verify against
     * @return true if signature is valid, false otherwise
     */
    public static boolean verify(PublicKey publicKey, byte[] signatureBytes, byte[]... components) {
        try {
            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(publicKey);

            // Update with all components in order
            for (byte[] component : components) {
                signature.update(component);
            }

            return signature.verify(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // Verification failures should return false, not throw
            return false;
        }
    }
}
