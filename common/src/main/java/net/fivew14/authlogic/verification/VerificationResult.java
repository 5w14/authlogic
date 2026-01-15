package net.fivew14.authlogic.verification;

import java.security.PublicKey;
import java.util.UUID;

/**
 * Result of verification attempt.
 * Contains success status and player information if successful.
 */
public class VerificationResult {
    public final boolean success;
    public final UUID playerUUID;
    public final String username;
    public final PublicKey clientPublicKey;
    public final String failureReason;

    /**
     * Whether the client's public key should be stored for TOFU verification.
     * <p>
     * - true for offline mode: the key is derived from password and should be consistent
     * - false for online mode: the key is a Mojang certificate that can be regenerated
     */
    public final boolean shouldStoreKeyForTOFU;

    /**
     * Whether this authentication used online mode (Mojang-verified).
     * <p>
     * - true: player authenticated with Mojang certificate (online mode)
     * - false: player authenticated with password-derived key (offline mode)
     * <p>
     * This is used to prevent offline-mode impersonation of online-mode players.
     */
    public final boolean isOnlineMode;

    private VerificationResult(boolean success, UUID playerUUID, String username,
                               PublicKey clientPublicKey, String failureReason,
                               boolean shouldStoreKeyForTOFU, boolean isOnlineMode) {
        this.success = success;
        this.playerUUID = playerUUID;
        this.username = username;
        this.clientPublicKey = clientPublicKey;
        this.failureReason = failureReason;
        this.shouldStoreKeyForTOFU = shouldStoreKeyForTOFU;
        this.isOnlineMode = isOnlineMode;
    }

    /**
     * Creates a successful verification result for offline mode.
     * The public key WILL be stored for TOFU verification.
     *
     * @param uuid     Player's UUID
     * @param username Player's username
     * @param key      Client's public key (password-derived)
     * @return Success result
     */
    public static VerificationResult successOffline(UUID uuid, String username, PublicKey key) {
        return new VerificationResult(true, uuid, username, key, null, true, false);
    }

    /**
     * Creates a successful verification result for online mode.
     * The public key will NOT be stored for TOFU (Mojang certificates can rotate).
     * The username will be recorded as an online-mode player to prevent impersonation.
     *
     * @param uuid     Player's UUID
     * @param username Player's username
     * @param key      Client's public key (Mojang certificate - not stored)
     * @return Success result
     */
    public static VerificationResult successOnline(UUID uuid, String username, PublicKey key) {
        return new VerificationResult(true, uuid, username, key, null, false, true);
    }

    /**
     * Creates a successful verification result.
     *
     * @param uuid     Player's UUID
     * @param username Player's username
     * @param key      Client's public key
     * @return Success result
     * @deprecated Use {@link #successOffline} or {@link #successOnline} instead
     */
    @Deprecated
    public static VerificationResult success(UUID uuid, String username, PublicKey key) {
        // Default to offline behavior for backwards compatibility
        return successOffline(uuid, username, key);
    }

    /**
     * Creates a failed verification result.
     *
     * @param reason Failure reason
     * @return Failure result
     */
    public static VerificationResult failure(String reason) {
        return new VerificationResult(false, null, null, null, reason, false, false);
    }
}
