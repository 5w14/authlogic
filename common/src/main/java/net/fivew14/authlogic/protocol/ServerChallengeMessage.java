package net.fivew14.authlogic.protocol;

import net.fivew14.authlogic.crypto.SignatureProvider;
import net.minecraft.network.FriendlyByteBuf;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * Server → Client challenge message.
 * Contains server's temporary key, constant public key, nonce, and signature.
 * <p>
 * Format: serverTempKey | serverPublicKey | serverNonce | signature
 */
public class ServerChallengeMessage {
    public final PublicKey serverTempKey;      // X25519 ephemeral key
    public final PublicKey serverPublicKey;    // RSA constant key
    public final long serverNonce;             // Random nonce
    public final byte[] signature;             // Signature over all above

    public ServerChallengeMessage(PublicKey serverTempKey, PublicKey serverPublicKey,
                                  long serverNonce, byte[] signature) {
        this.serverTempKey = serverTempKey;
        this.serverPublicKey = serverPublicKey;
        this.serverNonce = serverNonce;
        this.signature = signature;
    }

    /**
     * Creates and signs a new server challenge message.
     * Signs: (serverPublicKey || serverTempKey || serverNonce)
     *
     * @param serverTempKeys  Temporary X25519 keypair
     * @param serverConstKeys Constant RSA keypair
     * @param nonce           Random nonce
     * @return Signed challenge message
     */
    public static ServerChallengeMessage create(KeyPair serverTempKeys, KeyPair serverConstKeys, long nonce) {
        byte[] tempKeyBytes = SerializationUtil.serializePublicKey(serverTempKeys.getPublic());
        byte[] constKeyBytes = SerializationUtil.serializePublicKey(serverConstKeys.getPublic());
        byte[] nonceBytes = SerializationUtil.serializeLong(nonce);

        // Sign: serverPublicKey || serverTempKey || serverNonce
        byte[] signature = SignatureProvider.sign(
                serverConstKeys.getPrivate(),
                constKeyBytes,
                tempKeyBytes,
                nonceBytes
        );

        return new ServerChallengeMessage(
                serverTempKeys.getPublic(),
                serverConstKeys.getPublic(),
                nonce,
                signature
        );
    }

    /**
     * Verifies the signature on this message.
     *
     * @return true if signature is valid
     */
    public boolean verify() {
        byte[] tempKeyBytes = SerializationUtil.serializePublicKey(serverTempKey);
        byte[] constKeyBytes = SerializationUtil.serializePublicKey(serverPublicKey);
        byte[] nonceBytes = SerializationUtil.serializeLong(serverNonce);

        return SignatureProvider.verify(
                serverPublicKey,
                signature,
                constKeyBytes,
                tempKeyBytes,
                nonceBytes
        );
    }

    /**
     * Serializes this message to bytes.
     * Format: [tempKeyLen][tempKey][publicKeyLen][publicKey][nonce][sigLen][signature]
     *
     * @return Serialized bytes
     */
    public byte[] toBytes() {
        byte[] tempKeyBytes = SerializationUtil.serializePublicKey(serverTempKey);
        byte[] publicKeyBytes = SerializationUtil.serializePublicKey(serverPublicKey);

        ByteBuffer buffer = ByteBuffer.allocate(
                4 + tempKeyBytes.length +
                        4 + publicKeyBytes.length +
                        8 +
                        4 + signature.length
        );

        buffer.putInt(tempKeyBytes.length);
        buffer.put(tempKeyBytes);

        buffer.putInt(publicKeyBytes.length);
        buffer.put(publicKeyBytes);

        buffer.putLong(serverNonce);

        buffer.putInt(signature.length);
        buffer.put(signature);

        return buffer.array();
    }

    /**
     * Deserializes a message from bytes.
     *
     * @param data Serialized bytes
     * @return Deserialized message
     */
    public static ServerChallengeMessage fromBytes(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);

        PublicKey tempKey = SerializationUtil.readPublicKey(buffer, "X25519");
        PublicKey publicKey = SerializationUtil.readPublicKey(buffer, "RSA");
        long nonce = buffer.getLong();
        byte[] signature = SerializationUtil.deserializeBytes(buffer);

        return new ServerChallengeMessage(tempKey, publicKey, nonce, signature);
    }

    /**
     * Writes this message to a Minecraft FriendlyByteBuf.
     *
     * @param buf Buffer to write to
     */
    public void writeToBuf(FriendlyByteBuf buf) {
        byte[] data = toBytes();
        buf.writeInt(data.length);
        buf.writeBytes(data);
    }

    /**
     * Reads a message from a Minecraft FriendlyByteBuf.
     *
     * @param buf Buffer to read from
     * @return Deserialized message
     */
    public static ServerChallengeMessage fromBuf(FriendlyByteBuf buf) {
        int length = buf.readInt();
        byte[] data = new byte[length];
        buf.readBytes(data);
        return fromBytes(data);
    }
}
