package net.fivew14.authlogic.protocol;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;

import java.nio.ByteBuffer;
import java.security.PublicKey;

/**
 * Client → Server response message.
 * Contains verification type, server nonce (echo), client nonce, client temp key, and encrypted payload.
 * <p>
 * The server nonce is echoed outside the encrypted payload to allow the server to correlate
 * this response with the correct pending authentication state before decryption.
 * <p>
 * Format: verificationType | serverNonce | clientNonce | clientTempKey | encryptedPayload
 */
public class ClientResponseMessage {
    public final ResourceLocation verificationType;  // "authlogic:offline" or "authlogic:online"
    public final long serverNonce;                   // Echo of server's nonce for correlation
    public final long clientNonce;
    public final PublicKey clientTempKey;            // X25519 ephemeral key
    public final byte[] encryptedPayload;            // AES-GCM encrypted

    public ClientResponseMessage(ResourceLocation verificationType, long serverNonce, long clientNonce,
                                 PublicKey clientTempKey, byte[] encryptedPayload) {
        this.verificationType = verificationType;
        this.serverNonce = serverNonce;
        this.clientNonce = clientNonce;
        this.clientTempKey = clientTempKey;
        this.encryptedPayload = encryptedPayload;
    }

    /**
     * Creates a new client response message.
     *
     * @param type        Verification type (offline or online)
     * @param serverNonce Server's nonce (echoed for correlation)
     * @param clientNonce Client's random nonce
     * @param tempKey     Client's ephemeral X25519 public key
     * @param encrypted   Encrypted payload bytes
     * @return Client response message
     */
    public static ClientResponseMessage create(ResourceLocation type, long serverNonce, long clientNonce,
                                               PublicKey tempKey, byte[] encrypted) {
        return new ClientResponseMessage(type, serverNonce, clientNonce, tempKey, encrypted);
    }

    /**
     * Serializes this message to bytes.
     * Format: [namespace][path][serverNonce][clientNonce][tempKeyLen][tempKey][payloadLen][payload]
     *
     * @return Serialized bytes
     */
    public byte[] toBytes() {
        byte[] namespaceBytes = SerializationUtil.serializeString(verificationType.getNamespace());
        byte[] pathBytes = SerializationUtil.serializeString(verificationType.getPath());
        byte[] tempKeyBytes = SerializationUtil.serializePublicKey(clientTempKey);

        ByteBuffer buffer = ByteBuffer.allocate(
                namespaceBytes.length +
                        pathBytes.length +
                        8 + // serverNonce
                        8 + // clientNonce
                        4 + tempKeyBytes.length +
                        4 + encryptedPayload.length
        );

        buffer.put(namespaceBytes);
        buffer.put(pathBytes);
        buffer.putLong(serverNonce);
        buffer.putLong(clientNonce);

        buffer.putInt(tempKeyBytes.length);
        buffer.put(tempKeyBytes);

        buffer.putInt(encryptedPayload.length);
        buffer.put(encryptedPayload);

        return buffer.array();
    }

    /**
     * Deserializes a message from bytes.
     *
     * @param data Serialized bytes
     * @return Deserialized message
     */
    public static ClientResponseMessage fromBytes(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);

        String namespace = SerializationUtil.deserializeString(buffer);
        String path = SerializationUtil.deserializeString(buffer);
        ResourceLocation type = new ResourceLocation(namespace, path);

        long serverNonce = buffer.getLong();
        long clientNonce = buffer.getLong();

        PublicKey tempKey = SerializationUtil.readPublicKey(buffer, "X25519");
        byte[] payload = SerializationUtil.deserializeBytes(buffer);

        return new ClientResponseMessage(type, serverNonce, clientNonce, tempKey, payload);
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
    public static ClientResponseMessage fromBuf(FriendlyByteBuf buf) {
        int length = buf.readInt();
        byte[] data = new byte[length];
        buf.readBytes(data);
        return fromBytes(data);
    }
}
