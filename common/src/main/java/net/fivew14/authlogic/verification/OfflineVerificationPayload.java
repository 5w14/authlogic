package net.fivew14.authlogic.verification;

import com.mojang.logging.LogUtils;
import com.mojang.serialization.Codec;
import com.mojang.serialization.codecs.RecordCodecBuilder;
import net.fivew14.authlogic.crypto.SignatureProvider;
import net.fivew14.authlogic.protocol.SerializationUtil;
import net.fivew14.authlogic.server.state.CommonAuthState;
import net.minecraft.core.UUIDUtil;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

/**
 * Offline mode verification payload.
 * Implements VerificationPayload with Mojang's Codec API.
 */
public record OfflineVerificationPayload(
    UUID playerUUID,
    String username,
    byte[] clientPublicKeyBytes,
    byte[] signature
) implements VerificationPayload {
    
    private static final Logger LOGGER = LogUtils.getLogger();
    
    /**
     * Codec for serialization/deserialization using Mojang's Codec API.
     */
    public static final Codec<OfflineVerificationPayload> CODEC = RecordCodecBuilder.create(instance ->
        instance.group(
            UUIDUtil.CODEC.fieldOf("uuid").forGetter(OfflineVerificationPayload::playerUUID),
            Codec.STRING.fieldOf("username").forGetter(OfflineVerificationPayload::username),
            ByteArrayCodec.INSTANCE.fieldOf("public_key").forGetter(OfflineVerificationPayload::clientPublicKeyBytes),
            ByteArrayCodec.INSTANCE.fieldOf("signature").forGetter(OfflineVerificationPayload::signature)
        ).apply(instance, OfflineVerificationPayload::new)
    );
    
    @Override
    public VerificationPayloadType getType() {
        return VerificationPayloadType.OFFLINE;
    }
    
    @Override
    public UUID getPlayerUUID() {
        return playerUUID;
    }
    
    @Override
    public String getUsername() {
        return username;
    }
    
    @Override
    public PublicKey getClientPublicKey() {
        return SerializationUtil.deserializePublicKey(clientPublicKeyBytes, "RSA");
    }
    
    @Override
    public VerificationResult verify(CommonAuthState authState) throws VerificationException {
        try {
            PublicKey clientPublicKey = getClientPublicKey();
            
            // Verify client signature
            byte[] serverTempKeyBytes = SerializationUtil.serializePublicKey(authState.serverTemporaryKeys.publicKey);
            byte[] clientTempKeyBytes = SerializationUtil.serializePublicKey(authState.clientTemporaryKeys.publicKey);
            byte[] serverNonceBytes = SerializationUtil.serializeLong(authState.serverNonce);
            byte[] clientNonceBytes = SerializationUtil.serializeLong(authState.clientNonce);
            byte[] uuidBytes = SerializationUtil.serializeUUID(playerUUID);
            byte[] usernameBytes = SerializationUtil.serializeString(username);
            
            boolean signatureValid = net.fivew14.authlogic.crypto.SignatureProvider.verify(
                clientPublicKey,
                signature,
                serverTempKeyBytes,
                clientTempKeyBytes,
                serverNonceBytes,
                clientNonceBytes,
                uuidBytes,
                usernameBytes
            );
            
            if (!signatureValid) {
                throw new VerificationException("Invalid client signature");
            }
            
            LOGGER.debug("Offline verification successful for {}", username);
            return VerificationResult.successOffline(playerUUID, username, clientPublicKey);
            
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify offline payload", e);
        }
    }
    
    @Override
    public byte[] toBytes() {
        byte[] uuidBytes = SerializationUtil.serializeUUID(playerUUID);
        byte[] usernameBytes = SerializationUtil.serializeString(username);
        
        ByteBuffer buffer = ByteBuffer.allocate(
            uuidBytes.length +
            usernameBytes.length +
            4 + clientPublicKeyBytes.length +
            4 + signature.length
        );
        
        buffer.put(uuidBytes);
        buffer.put(usernameBytes);
        
        buffer.putInt(clientPublicKeyBytes.length);
        buffer.put(clientPublicKeyBytes);
        
        buffer.putInt(signature.length);
        buffer.put(signature);
        
        return buffer.array();
    }
    
    /**
     * Creates an OfflineVerificationPayload from raw bytes.
     * 
     * @param data Raw bytes
     * @return Payload
     */
    public static OfflineVerificationPayload fromBytes(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        
        UUID uuid = SerializationUtil.deserializeUUID(buffer);
        String username = SerializationUtil.deserializeString(buffer);
        byte[] publicKeyBytes = SerializationUtil.deserializeBytes(buffer);
        byte[] signature = SerializationUtil.deserializeBytes(buffer);
        
        return new OfflineVerificationPayload(uuid, username, publicKeyBytes, signature);
    }
    
    /**
     * Creates and signs a new offline verification payload.
     * 
     * Signature covers: serverTempKey || clientTempKey || serverNonce || clientNonce || UUID || username
     * 
     * @param uuid Player's UUID
     * @param username Player's username
     * @param clientPublicKey Client's RSA public key
     * @param clientPrivateKey Client's RSA private key (for signing)
     * @param serverTempKey Server's ephemeral public key
     * @param clientTempKey Client's ephemeral public key
     * @param serverNonce Server's nonce
     * @param clientNonce Client's nonce
     * @return Signed offline verification payload
     */
    public static OfflineVerificationPayload create(
        UUID uuid,
        String username,
        PublicKey clientPublicKey,
        PrivateKey clientPrivateKey,
        PublicKey serverTempKey,
        PublicKey clientTempKey,
        long serverNonce,
        long clientNonce
    ) {
        byte[] serverTempKeyBytes = SerializationUtil.serializePublicKey(serverTempKey);
        byte[] clientTempKeyBytes = SerializationUtil.serializePublicKey(clientTempKey);
        byte[] serverNonceBytes = SerializationUtil.serializeLong(serverNonce);
        byte[] clientNonceBytes = SerializationUtil.serializeLong(clientNonce);
        byte[] uuidBytes = SerializationUtil.serializeUUID(uuid);
        byte[] usernameBytes = SerializationUtil.serializeString(username);
        
        // Sign: serverTempKey || clientTempKey || serverNonce || clientNonce || UUID || username
        byte[] signature = SignatureProvider.sign(
            clientPrivateKey,
            serverTempKeyBytes,
            clientTempKeyBytes,
            serverNonceBytes,
            clientNonceBytes,
            uuidBytes,
            usernameBytes
        );
        
        byte[] clientPublicKeyBytes = SerializationUtil.serializePublicKey(clientPublicKey);
        return new OfflineVerificationPayload(uuid, username, clientPublicKeyBytes, signature);
    }
}
