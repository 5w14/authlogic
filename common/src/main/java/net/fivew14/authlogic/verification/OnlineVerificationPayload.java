package net.fivew14.authlogic.verification;

import com.mojang.logging.LogUtils;
import com.mojang.serialization.Codec;
import com.mojang.serialization.codecs.RecordCodecBuilder;
import net.fivew14.authlogic.crypto.MojangProfileFetcher;
import net.fivew14.authlogic.crypto.MojangPublicKeyFetcher;
import net.fivew14.authlogic.crypto.SignatureProvider;
import net.fivew14.authlogic.protocol.SerializationUtil;
import net.fivew14.authlogic.server.state.CommonAuthState;
import net.minecraft.core.UUIDUtil;
import org.slf4j.Logger;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Online mode verification payload.
 * Implements VerificationPayload with Mojang's Codec API.
 * Verifies both Mojang signature and UUID-username match.
 */
public record OnlineVerificationPayload(
    UUID playerUUID,
    String username,
    byte[] clientPublicKeyBytes,
    long expiresAtMillis,
    byte[] mojangSignature,
    byte[] signature
) implements VerificationPayload {
    
    private static final Logger LOGGER = LogUtils.getLogger();
    
    /**
     * Codec for serialization/deserialization using Mojang's Codec API.
     */
    public static final Codec<OnlineVerificationPayload> CODEC = RecordCodecBuilder.create(instance ->
        instance.group(
            UUIDUtil.CODEC.fieldOf("uuid").forGetter(OnlineVerificationPayload::playerUUID),
            Codec.STRING.fieldOf("username").forGetter(OnlineVerificationPayload::username),
            ByteArrayCodec.INSTANCE.fieldOf("public_key").forGetter(OnlineVerificationPayload::clientPublicKeyBytes),
            Codec.LONG.fieldOf("expires_at").forGetter(OnlineVerificationPayload::expiresAtMillis),
            ByteArrayCodec.INSTANCE.fieldOf("mojang_signature").forGetter(OnlineVerificationPayload::mojangSignature),
            ByteArrayCodec.INSTANCE.fieldOf("signature").forGetter(OnlineVerificationPayload::signature)
        ).apply(instance, OnlineVerificationPayload::new)
    );
    
    @Override
    public VerificationPayloadType getType() {
        return VerificationPayloadType.ONLINE;
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
            
            // 1. Check expiry
            if (expiresAtMillis < System.currentTimeMillis()) {
                throw new VerificationException("Client public key has expired");
            }
            
            // 2. Verify Mojang signature on the public key
            if (!verifyMojangSignature()) {
                throw new VerificationException("Invalid Mojang signature. Restart your game and/or launcher.");
            }
            LOGGER.debug("Mojang signature verified for {}", playerUUID);
            
            // 3. Verify UUID matches username via Mojang API
            if (!verifyUUIDMatchesUsername()) {
                throw new VerificationException(
                    "UUID-username mismatch: UUID " + playerUUID + " does not belong to '" + username + "'"
                );
            }
            LOGGER.debug("UUID-username match verified for {} = {}", playerUUID, username);
            
            // 4. Verify client signature
            byte[] serverTempKeyBytes = SerializationUtil.serializePublicKey(authState.serverTemporaryKeys.publicKey);
            byte[] clientTempKeyBytes = SerializationUtil.serializePublicKey(authState.clientTemporaryKeys.publicKey);
            byte[] serverNonceBytes = SerializationUtil.serializeLong(authState.serverNonce);
            byte[] clientNonceBytes = SerializationUtil.serializeLong(authState.clientNonce);
            byte[] uuidBytes = SerializationUtil.serializeUUID(playerUUID);
            byte[] expiryBytes = SerializationUtil.serializeLong(expiresAtMillis);
            
            boolean signatureValid = net.fivew14.authlogic.crypto.SignatureProvider.verify(
                clientPublicKey,
                signature,
                serverTempKeyBytes,
                clientTempKeyBytes,
                serverNonceBytes,
                clientNonceBytes,
                uuidBytes,
                expiryBytes,
                mojangSignature
            );
            
            if (!signatureValid) {
                throw new VerificationException("Invalid client signature");
            }
            
            LOGGER.debug("Online verification successful for {} ({})", username, playerUUID);
            return VerificationResult.successOnline(playerUUID, username, clientPublicKey);
            
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify online payload", e);
        }
    }
    
    /**
     * Verifies Mojang's signature on the client public key.
     * 
     * Algorithm:
     * 1. Fetch Mojang's public keys from API (cached)
     * 2. Construct payload: UUID (16 bytes) || expiry (8 bytes big-endian) || publicKey bytes
     * 3. Try verifying signature with each Mojang public key using SHA1withRSA
     * 4. Return true if any key validates the signature
     * 
     * @return true if Mojang signature is valid
     */
    private boolean verifyMojangSignature() {
        try {
            // 1. Construct payload buffer: UUID + expiry + public key
            byte[] payload = buildMojangPayloadBuffer();
            
            // 2. Get Mojang public keys (uses cache)
            List<PublicKey> mojangKeys = MojangPublicKeyFetcher.getPublicKeys()
                .get(5, TimeUnit.SECONDS);
            
            // 3. Try verifying with each Mojang key
            for (PublicKey mojangKey : mojangKeys) {
                if (verifySignatureWithKey(mojangKey, payload)) {
                    return true;
                }
            }
            
            LOGGER.warn("Mojang signature verification failed for UUID {}", playerUUID);
            return false;
            
        } catch (Exception e) {
            LOGGER.error("Failed to verify Mojang signature for UUID {}", playerUUID, e);
            return false;
        }
    }
    
    /**
     * Builds the payload buffer that Mojang signs.
     * Format: UUID (16 bytes) || expiry (8 bytes big-endian) || publicKey bytes
     */
    private byte[] buildMojangPayloadBuffer() {
        byte[] uuidBytes = SerializationUtil.serializeUUID(playerUUID);
        byte[] expiryBytes = SerializationUtil.serializeLong(expiresAtMillis);

        // Concatenate: UUID + expiry + publicKey
        ByteBuffer buffer = ByteBuffer.allocate(
            uuidBytes.length + expiryBytes.length + clientPublicKeyBytes.length
        );
        buffer.put(uuidBytes);
        buffer.put(expiryBytes);
        buffer.put(clientPublicKeyBytes);
        
        return buffer.array();
    }
    
    /**
     * Verifies signature using a specific Mojang public key.
     * Uses SHA1withRSA algorithm as per Mojang's specification.
     */
    private boolean verifySignatureWithKey(PublicKey mojangKey, byte[] payload) {
        try {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initVerify(mojangKey);
            sig.update(payload);
            return sig.verify(mojangSignature);
        } catch (Exception e) {
            // Silent failure - try next key
            return false;
        }
    }
    
    /**
     * Verifies that the UUID matches the username via Mojang's session server API.
     * This ensures the player is who they claim to be.
     * 
     * @return true if UUID-username matches according to Mojang
     */
    private boolean verifyUUIDMatchesUsername() {
        try {
            Boolean matches = MojangProfileFetcher.verifyUUIDMatchesUsername(playerUUID, username)
                .get(5, TimeUnit.SECONDS);
            return matches != null && matches;
        } catch (Exception e) {
            LOGGER.error("Failed to verify UUID-username match for {} ({})", username, playerUUID, e);
            return false;
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
            8 +
            4 + mojangSignature.length +
            4 + signature.length
        );
        
        buffer.put(uuidBytes);
        buffer.put(usernameBytes);
        
        buffer.putInt(clientPublicKeyBytes.length);
        buffer.put(clientPublicKeyBytes);
        
        buffer.putLong(expiresAtMillis);
        
        buffer.putInt(mojangSignature.length);
        buffer.put(mojangSignature);
        
        buffer.putInt(signature.length);
        buffer.put(signature);
        
        return buffer.array();
    }
    
    /**
     * Creates an OnlineVerificationPayload from raw bytes.
     * 
     * @param data Raw bytes
     * @return Payload
     */
    public static OnlineVerificationPayload fromBytes(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        
        UUID uuid = SerializationUtil.deserializeUUID(buffer);
        String username = SerializationUtil.deserializeString(buffer);
        byte[] publicKeyBytes = SerializationUtil.deserializeBytes(buffer);
        long expiry = buffer.getLong();
        byte[] mojangSig = SerializationUtil.deserializeBytes(buffer);
        byte[] signature = SerializationUtil.deserializeBytes(buffer);
        
        return new OnlineVerificationPayload(uuid, username, publicKeyBytes, expiry, mojangSig, signature);
    }
    
    /**
     * Creates and signs a new online verification payload.
     * 
     * Signature covers: serverTempKey || clientTempKey || serverNonce || clientNonce || UUID || expiry || mojangSignature
     * 
     * @param uuid Player's UUID
     * @param username Player's username
     * @param clientPublicKey Client's RSA public key (Mojang-signed)
     * @param clientPrivateKey Client's RSA private key (for signing)
     * @param expiresAtMillis Expiry timestamp for client public key
     * @param mojangSig Mojang's signature on the public key
     * @param serverTempKey Server's ephemeral public key
     * @param clientTempKey Client's ephemeral public key
     * @param serverNonce Server's nonce
     * @param clientNonce Client's nonce
     * @return Signed online verification payload
     */
    public static OnlineVerificationPayload create(
        UUID uuid,
        String username,
        PublicKey clientPublicKey,
        PrivateKey clientPrivateKey,
        long expiresAtMillis,
        byte[] mojangSig,
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
        byte[] expiryBytes = SerializationUtil.serializeLong(expiresAtMillis);
        
        // Sign: serverTempKey || clientTempKey || serverNonce || clientNonce || UUID || expiry || mojangSignature
        byte[] signature = SignatureProvider.sign(
            clientPrivateKey,
            serverTempKeyBytes,
            clientTempKeyBytes,
            serverNonceBytes,
            clientNonceBytes,
            uuidBytes,
            expiryBytes,
            mojangSig
        );
        
        byte[] clientPublicKeyBytes = SerializationUtil.serializePublicKey(clientPublicKey);
        return new OnlineVerificationPayload(uuid, username, clientPublicKeyBytes, expiresAtMillis, mojangSig, signature);
    }
}
