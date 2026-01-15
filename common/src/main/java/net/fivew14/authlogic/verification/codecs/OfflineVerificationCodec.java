package net.fivew14.authlogic.verification.codecs;

import net.fivew14.authlogic.server.state.CommonAuthState;
import net.fivew14.authlogic.verification.OfflineVerificationPayload;
import net.fivew14.authlogic.verification.VerificationCodec;
import net.fivew14.authlogic.verification.VerificationException;
import net.fivew14.authlogic.verification.VerificationResult;
import net.minecraft.resources.ResourceLocation;

/**
 * Verification codec for offline mode authentication.
 * Type: "authlogic:offline"
 */
public class OfflineVerificationCodec implements VerificationCodec {
    private static final ResourceLocation TYPE = new ResourceLocation("authlogic", "offline");

    @Override
    public VerificationResult verify(byte[] encryptedPayload, CommonAuthState authState)
            throws VerificationException {
        try {
            // Decrypt payload
            byte[] decrypted = authState.decryptBlob(encryptedPayload);

            // Deserialize payload
            OfflineVerificationPayload payload = OfflineVerificationPayload.fromBytes(decrypted);

            // Verify
            return payload.verify(authState);

        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Failed to verify offline payload", e);
        }
    }

    @Override
    public byte[] encode(Object payload, CommonAuthState authState) {
        if (!(payload instanceof OfflineVerificationPayload)) {
            throw new IllegalArgumentException("Expected OfflineVerificationPayload, got: " + payload.getClass());
        }

        OfflineVerificationPayload offlinePayload = (OfflineVerificationPayload) payload;
        byte[] serialized = offlinePayload.toBytes();
        return authState.encryptBlob(serialized);
    }

    @Override
    public ResourceLocation getType() {
        return TYPE;
    }
}
