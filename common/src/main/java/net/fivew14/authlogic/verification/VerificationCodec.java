package net.fivew14.authlogic.verification;

import net.fivew14.authlogic.server.state.CommonAuthState;
import net.minecraft.resources.ResourceLocation;

/**
 * CODEC-style interface for verification handlers.
 * Allows mods to register custom authentication methods.
 */
public interface VerificationCodec {

    /**
     * Verifies encrypted payload and returns authentication result.
     *
     * @param encryptedPayload AES-GCM encrypted payload bytes
     * @param authState        Authentication state with keys and nonces
     * @return Verification result with player info
     * @throws VerificationException on any failure - triggers immediate disconnect
     */
    VerificationResult verify(byte[] encryptedPayload, CommonAuthState authState)
            throws VerificationException;

    /**
     * Encodes payload and encrypts for transmission.
     *
     * @param payload   Payload object (OfflinePayload or OnlinePayload)
     * @param authState Authentication state with keys
     * @return Encrypted payload bytes
     */
    byte[] encode(Object payload, CommonAuthState authState);

    /**
     * Gets the ResourceLocation identifier for this codec.
     *
     * @return Codec type (e.g., "authlogic:offline")
     */
    ResourceLocation getType();
}
