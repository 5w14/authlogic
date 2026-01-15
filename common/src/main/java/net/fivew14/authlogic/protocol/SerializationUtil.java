package net.fivew14.authlogic.protocol;

import net.minecraft.network.FriendlyByteBuf;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility class for serializing and deserializing protocol message components.
 * <p>
 * Most serialization is now handled directly by FriendlyByteBuf:
 * - writePublicKey() / readPublicKey() for RSA keys
 * - writeUUID() / readUUID() for UUIDs
 * - writeUtf() / readUtf() for strings
 * - writeLong() / readLong() for longs
 * - writeByteArray() / readByteArray() for byte arrays
 * <p>
 * This class provides additional utilities for:
 * - X25519 keys (FriendlyByteBuf only handles RSA)
 * - Private key serialization
 * - ByteBuffer-based operations for legacy code
 * <p>
 * SECURITY: All deserialization methods include bounds checking to prevent
 * denial-of-service attacks via maliciously crafted packets.
 */
public class SerializationUtil {

    /**
     * Maximum allowed string length in bytes (32KB).
     * Prevents memory exhaustion from malicious packets.
     */
    private static final int MAX_STRING_LENGTH = 32768;

    /**
     * Maximum allowed byte array length (1MB).
     * Prevents memory exhaustion from malicious packets.
     */
    private static final int MAX_BYTE_ARRAY_LENGTH = 1048576;

    /**
     * Maximum allowed public key length (8KB).
     * RSA-4096 keys are about 550 bytes, so this is very generous.
     */
    private static final int MAX_PUBLIC_KEY_LENGTH = 8192;

    // ==================== X25519 Key Serialization ====================
    // FriendlyByteBuf.readPublicKey() only handles RSA, so we need custom X25519 handling

    /**
     * Writes an X25519 public key to a FriendlyByteBuf.
     *
     * @param buf Buffer to write to
     * @param key X25519 public key
     */
    public static void writeX25519PublicKey(FriendlyByteBuf buf, PublicKey key) {
        buf.writeByteArray(key.getEncoded());
    }

    /**
     * Reads an X25519 public key from a FriendlyByteBuf.
     *
     * @param buf Buffer to read from
     * @return X25519 public key
     */
    public static PublicKey readX25519PublicKey(FriendlyByteBuf buf) {
        byte[] keyBytes = buf.readByteArray();
        return deserializePublicKey(keyBytes, "X25519");
    }

    // ==================== Private Key Serialization ====================

    /**
     * Serializes a private key to bytes.
     *
     * @param key Private key (RSA or X25519)
     * @return Encoded key bytes
     */
    public static byte[] serializePrivateKey(PrivateKey key) {
        return key.getEncoded();
    }

    /**
     * Deserializes a private key from bytes.
     *
     * @param data      Encoded key bytes
     * @param algorithm "RSA" or "X25519"
     * @return Private key
     * @throws RuntimeException if deserialization fails
     */
    public static PrivateKey deserializePrivateKey(byte[] data, String algorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(data);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize private key for algorithm: " + algorithm, e);
        }
    }

    // ==================== Public Key Deserialization ====================

    /**
     * Deserializes a public key from bytes.
     *
     * @param data      Encoded key bytes
     * @param algorithm "RSA" or "X25519"
     * @return Public key
     * @throws RuntimeException if deserialization fails
     */
    public static PublicKey deserializePublicKey(byte[] data, String algorithm) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(data);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize public key for algorithm: " + algorithm, e);
        }
    }

    // ==================== Legacy ByteBuffer Methods ====================
    // These are kept for backward compatibility with existing code using ByteBuffer

    /**
     * Serializes a public key to bytes.
     *
     * @param key Public key (RSA or X25519)
     * @return Encoded key bytes
     */
    public static byte[] serializePublicKey(PublicKey key) {
        return key.getEncoded();
    }

    /**
     * Serializes a long to 8 bytes.
     * Used for signature generation where we need raw bytes.
     *
     * @param value Long value
     * @return 8-byte array
     */
    public static byte[] serializeLong(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(value);
        return buffer.array();
    }

    /**
     * Serializes a UUID to 16 bytes.
     * Used for signature generation where we need raw bytes.
     *
     * @param uuid UUID to serialize
     * @return 16-byte array
     */
    public static byte[] serializeUUID(java.util.UUID uuid) {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        return buffer.array();
    }

    /**
     * Deserializes a UUID from a ByteBuffer (advances buffer position).
     *
     * @param buffer ByteBuffer to read from
     * @return UUID
     */
    public static java.util.UUID deserializeUUID(ByteBuffer buffer) {
        long mostSigBits = buffer.getLong();
        long leastSigBits = buffer.getLong();
        return new java.util.UUID(mostSigBits, leastSigBits);
    }

    /**
     * Serializes a string with length prefix (4 bytes) + UTF-8 bytes.
     * Used for signature generation where we need raw bytes.
     *
     * @param str String to serialize
     * @return Length-prefixed string bytes
     */
    public static byte[] serializeString(String str) {
        byte[] strBytes = str.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(4 + strBytes.length);
        buffer.putInt(strBytes.length);
        buffer.put(strBytes);
        return buffer.array();
    }

    /**
     * Deserializes a string from a ByteBuffer (advances buffer position).
     *
     * @param buffer ByteBuffer to read from
     * @return Deserialized string
     * @throws IllegalArgumentException if string length exceeds maximum or is negative
     */
    public static String deserializeString(ByteBuffer buffer) {
        int length = buffer.getInt();
        if (length < 0 || length > MAX_STRING_LENGTH) {
            throw new IllegalArgumentException(
                    "String length out of bounds: " + length + " (max: " + MAX_STRING_LENGTH + ")"
            );
        }
        byte[] strBytes = new byte[length];
        buffer.get(strBytes);
        return new String(strBytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Reads a length-prefixed byte array from a ByteBuffer.
     *
     * @param buffer ByteBuffer to read from
     * @return Deserialized byte array
     * @throws IllegalArgumentException if array length exceeds maximum or is negative
     */
    public static byte[] deserializeBytes(ByteBuffer buffer) {
        int length = buffer.getInt();
        if (length < 0 || length > MAX_BYTE_ARRAY_LENGTH) {
            throw new IllegalArgumentException(
                    "Byte array length out of bounds: " + length + " (max: " + MAX_BYTE_ARRAY_LENGTH + ")"
            );
        }
        byte[] data = new byte[length];
        buffer.get(data);
        return data;
    }

    /**
     * Reads a public key from a ByteBuffer with length prefix.
     *
     * @param buffer    ByteBuffer to read from
     * @param algorithm "RSA" or "X25519"
     * @return Public key
     * @throws IllegalArgumentException if key length exceeds maximum or is negative
     */
    public static PublicKey readPublicKey(ByteBuffer buffer, String algorithm) {
        int length = buffer.getInt();
        if (length < 0 || length > MAX_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException(
                    "Public key length out of bounds: " + length + " (max: " + MAX_PUBLIC_KEY_LENGTH + ")"
            );
        }
        byte[] keyBytes = new byte[length];
        buffer.get(keyBytes);
        return deserializePublicKey(keyBytes, algorithm);
    }

    /**
     * Concatenates multiple byte arrays into one.
     * Used for building signature payloads.
     *
     * @param arrays Arrays to concatenate
     * @return Concatenated byte array
     */
    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        for (byte[] array : arrays) {
            buffer.put(array);
        }

        return buffer.array();
    }
}
