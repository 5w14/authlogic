package net.fivew14.authlogic.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Derives deterministic RSA keypairs from password hashes and server public keys.
 * This allows clients to regenerate the same keypair across sessions and server IP changes.
 * <p>
 * SECURITY: Never accepts plain-text passwords. All methods require pre-hashed passwords.
 * Uses PBKDF2-HMAC-SHA256 with 100,000 iterations to derive a seed, then uses HKDF
 * to expand the seed into deterministic random bytes for RSA key generation.
 * <p>
 * PORTABILITY: Uses a custom deterministic PRNG implementation to ensure consistent
 * key generation across all JVM implementations.
 */
public class PasswordBasedKeyDerivation {
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 100_000;
    private static final int KEY_LENGTH_BITS = 256; // 32 bytes for initial seed
    private static final int RSA_KEY_SIZE = 2048;

    /**
     * Hashes a password using SHA-256.
     * This should be called immediately when password is received to avoid storing plain text.
     *
     * @param plainPassword Plain text password (will be hashed immediately)
     * @return SHA-256 hash as hex string
     */
    public static String hashPassword(String plainPassword) {
        byte[] hash = Hasher.sha256(plainPassword);
        return bytesToHex(hash);
    }

    /**
     * Derives a deterministic RSA keypair from a password hash and server public key.
     * Same password hash + server key will always produce the same keypair.
     * <p>
     * SECURITY: This method expects a SHA-256 hash (64 hex chars), NOT a plain password.
     * PORTABILITY: Uses a custom deterministic PRNG that produces identical results
     * across all JVM implementations.
     *
     * @param passwordHash    SHA-256 hash of the password (64 hex characters)
     * @param serverPublicKey Server's RSA public key (used as salt)
     * @return Deterministic RSA keypair
     * @throws RuntimeException         if key derivation fails
     * @throws IllegalArgumentException if passwordHash is not a valid SHA-256 hash
     */
    public static KeyPair deriveKeyPair(String passwordHash, PublicKey serverPublicKey) {
        // Validate that we received a hash, not a plain password
        if (passwordHash == null || passwordHash.length() != 64) {
            throw new IllegalArgumentException(
                    "Password hash must be a 64-character hex string (SHA-256 hash). " +
                            "Use hashPassword() to hash plain passwords before calling this method."
            );
        }

        try {
            // Use server public key bytes as salt for PBKDF2
            byte[] salt = serverPublicKey.getEncoded();

            // Derive initial key material using PBKDF2
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            KeySpec spec = new PBEKeySpec(
                    passwordHash.toCharArray(),
                    salt,
                    ITERATIONS,
                    KEY_LENGTH_BITS
            );
            byte[] derivedKey = factory.generateSecret(spec).getEncoded();

            // Use our portable deterministic PRNG
            SecureRandom deterministicRandom = new DeterministicSecureRandom(derivedKey);

            // Generate RSA keypair deterministically
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_SIZE, deterministicRandom);

            return keyPairGenerator.generateKeyPair();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to derive keypair from password hash", e);
        }
    }

    /**
     * Derives a deterministic RSA keypair from a password hash and server public key bytes.
     * Convenience method that reconstructs the PublicKey from bytes.
     *
     * @param passwordHash         SHA-256 hash of the password (64 hex characters)
     * @param serverPublicKeyBytes Server's RSA public key as encoded bytes
     * @return Deterministic RSA keypair
     * @throws RuntimeException if key derivation fails
     */
    public static KeyPair deriveKeyPair(String passwordHash, byte[] serverPublicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
            PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);
            return deriveKeyPair(passwordHash, serverPublicKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive keypair from password hash and key bytes", e);
        }
    }

    /**
     * Converts byte array to hex string.
     *
     * @param bytes Bytes to convert
     * @return Hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * A deterministic SecureRandom implementation that produces identical output
     * across all JVM implementations given the same seed.
     * <p>
     * Uses HMAC-SHA256 in counter mode (similar to HKDF-Expand) to generate
     * deterministic pseudo-random bytes.
     * <p>
     * SECURITY NOTE: This is ONLY for deterministic key derivation where we need
     * portability. For general random number generation, use regular SecureRandom.
     */
    private static class DeterministicSecureRandom extends SecureRandom {
        private final byte[] seed;
        private long counter = 0;
        private byte[] currentBlock = null;
        private int blockOffset = 0;

        public DeterministicSecureRandom(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            int offset = 0;
            while (offset < bytes.length) {
                if (currentBlock == null || blockOffset >= currentBlock.length) {
                    // Generate next block using HMAC-SHA256(seed, counter)
                    currentBlock = generateBlock();
                    blockOffset = 0;
                }

                int toCopy = Math.min(bytes.length - offset, currentBlock.length - blockOffset);
                System.arraycopy(currentBlock, blockOffset, bytes, offset, toCopy);
                offset += toCopy;
                blockOffset += toCopy;
            }
        }

        private byte[] generateBlock() {
            try {
                // Use HMAC-SHA256(seed, counter) to generate deterministic blocks
                javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(seed, "HmacSHA256");
                mac.init(keySpec);

                // Include counter in the input
                ByteBuffer counterBuffer = ByteBuffer.allocate(8);
                counterBuffer.putLong(counter++);
                mac.update(counterBuffer.array());

                return mac.doFinal();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate deterministic random block", e);
            }
        }

        @Override
        public int nextInt() {
            byte[] bytes = new byte[4];
            nextBytes(bytes);
            return ByteBuffer.wrap(bytes).getInt();
        }

        @Override
        public long nextLong() {
            byte[] bytes = new byte[8];
            nextBytes(bytes);
            return ByteBuffer.wrap(bytes).getLong();
        }

        @Override
        public boolean nextBoolean() {
            byte[] bytes = new byte[1];
            nextBytes(bytes);
            return (bytes[0] & 1) != 0;
        }

        @Override
        public float nextFloat() {
            return (nextInt() >>> 8) / ((float) (1 << 24));
        }

        @Override
        public double nextDouble() {
            return (nextLong() >>> 11) / (double) (1L << 53);
        }

        @Override
        public void setSeed(long seed) {
            // Ignore - we use our own seeding mechanism
        }

        @Override
        public void setSeed(byte[] seed) {
            // Ignore - we use our own seeding mechanism
        }

        @Override
        public byte[] generateSeed(int numBytes) {
            byte[] bytes = new byte[numBytes];
            nextBytes(bytes);
            return bytes;
        }
    }
}
