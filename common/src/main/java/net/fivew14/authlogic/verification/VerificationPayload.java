package net.fivew14.authlogic.verification;

import com.mojang.serialization.Codec;
import net.fivew14.authlogic.server.state.CommonAuthState;

import java.security.PublicKey;
import java.util.UUID;

/**
 * Base interface for verification payloads using Mojang's Codec API.
 * Uses dispatch codec on the "type" field to select the appropriate payload type.
 */
public interface VerificationPayload {

    /**
     * The dispatch codec that selects payload type based on the "type" field.
     */
    Codec<VerificationPayload> DISPATCH_CODEC = VerificationPayloadType.TYPE_CODEC
            .dispatch("type", VerificationPayload::getType, VerificationPayloadType::codec);

    /**
     * Gets the type of this payload.
     *
     * @return Payload type
     */
    VerificationPayloadType getType();

    /**
     * Gets the player UUID from this payload.
     *
     * @return Player UUID
     */
    UUID getPlayerUUID();

    /**
     * Gets the player username from this payload.
     *
     * @return Player username
     */
    String getUsername();

    /**
     * Gets the client's public key from this payload.
     *
     * @return Client RSA public key
     */
    PublicKey getClientPublicKey();

    /**
     * Verifies the payload signature and any additional verification logic.
     *
     * @param authState Authentication state with keys and nonces
     * @return Verification result
     * @throws VerificationException if verification fails
     */
    VerificationResult verify(CommonAuthState authState) throws VerificationException;

    /**
     * Serializes this payload to bytes for encryption.
     *
     * @return Serialized bytes
     */
    byte[] toBytes();
}
