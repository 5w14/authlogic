package net.fivew14.authlogic.verification.codecs;

import net.fivew14.authlogic.server.state.CommonAuthState;
import net.fivew14.authlogic.verification.OnlineVerificationPayload;
import net.fivew14.authlogic.verification.VerificationCodec;
import net.fivew14.authlogic.verification.VerificationException;
import net.fivew14.authlogic.verification.VerificationResult;
import net.minecraft.resources.ResourceLocation;

/**
 * Verification codec for online mode authentication.
 * Type: "authlogic:online"
 * <p>
 * Verification includes:
 * - Mojang signature verification (public key is signed by Mojang)
 * - UUID-username match verification via Mojang session server
 * - Client signature verification
 * - Key expiration check
 */
public class OnlineVerificationCodec implements VerificationCodec {
    private static final ResourceLocation TYPE = new ResourceLocation("authlogic", "online");

    @Override
    public VerificationResult verify(byte[] encryptedPayload, CommonAuthState authState)
            throws VerificationException {
        try {
            // Decrypt payload
            byte[] decrypted = authState.decryptBlob(encryptedPayload);

            // Deserialize payload
            OnlineVerificationPayload payload = OnlineVerificationPayload.fromBytes(decrypted);

            // Verify (includes Mojang sig + UUID-username match)
            return payload.verify(authState);

        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify online payload", e);
        }
    }

    @Override
    public byte[] encode(Object payload, CommonAuthState authState) {
        if (!(payload instanceof OnlineVerificationPayload)) {
            throw new IllegalArgumentException("Expected OnlineVerificationPayload, got: " + payload.getClass());
        }

        OnlineVerificationPayload onlinePayload = (OnlineVerificationPayload) payload;
        byte[] serialized = onlinePayload.toBytes();
        return authState.encryptBlob(serialized);
    }

    @Override
    public ResourceLocation getType() {
        return TYPE;
    }
}
