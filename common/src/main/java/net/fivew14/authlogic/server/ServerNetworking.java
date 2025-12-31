package net.fivew14.authlogic.server;

import com.mojang.logging.LogUtils;
import io.netty.buffer.Unpooled;
import net.fivew14.authlogic.crypto.KeysProvider;
import net.fivew14.authlogic.crypto.OptionalKeyPair;
import net.fivew14.authlogic.protocol.ClientResponseMessage;
import net.fivew14.authlogic.protocol.ServerChallengeMessage;
import net.fivew14.authlogic.server.state.CommonAuthState;
import net.fivew14.authlogic.server.state.FinishedAuthState;
import net.fivew14.authlogic.server.state.InProgressAuthState;
import net.fivew14.authlogic.verification.VerificationCodec;
import net.fivew14.authlogic.verification.VerificationException;
import net.fivew14.authlogic.verification.VerificationRegistry;
import net.fivew14.authlogic.verification.VerificationResult;
import net.minecraft.network.FriendlyByteBuf;
import org.slf4j.Logger;

import java.security.KeyPair;

/**
 * Server-side networking for authentication protocol.
 * Handles server challenge generation and client response validation.
 * 
 * Authentication states are correlated using the server nonce, which is
 * echoed by the client in its response. This provides reliable protocol-level
 * correlation independent of transport-layer connection identifiers.
 */
public class ServerNetworking {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static ServerStorage storage;
    
    /**
     * Sets the server storage instance.
     * Must be called during initialization.
     * 
     * @param serverStorage Server storage instance
     */
    public static void setStorage(ServerStorage serverStorage) {
        storage = serverStorage;
    }
    
    /**
     * Gets the server storage instance.
     * 
     * @return Server storage
     * @throws IllegalStateException if storage not initialized
     */
    private static ServerStorage getStorage() {
        if (storage == null) {
            throw new IllegalStateException("ServerStorage not initialized. Call setStorage() first.");
        }
        return storage;
    }
    
    /**
     * Generates a server query (challenge) message for a new connection.
     * The server nonce is used as the correlation key for matching responses.
     * 
     * @return FriendlyByteBuf containing the challenge
     */
    public static FriendlyByteBuf getServerQuery() {
        try {
            // 1. Create new InProgressAuthState
            InProgressAuthState state = ServerAuthState.newAuthState();
            
            // 2. Generate temporary keypair
            KeyPair tempKeys = KeysProvider.generateTemporaryKeyPair();
            state.serverTemporaryKeys = OptionalKeyPair.of(tempKeys);
            
            // 3. Generate nonce (this becomes the correlation key)
            state.serverNonce = KeysProvider.generateNonce();
            
            // 4. Load server's constant RSA keypair
            KeyPair serverKeys = getStorage().getOrCreateServerKeyPair();
            state.serverConstPublicKey = serverKeys.getPublic();
            
            // 5. Create and sign challenge message
            ServerChallengeMessage message = ServerChallengeMessage.create(
                tempKeys,
                serverKeys,
                state.serverNonce
            );
            
            // 6. Store state keyed by server nonce
            ServerAuthState.STATE.put(state.serverNonce, state);
            
            // 7. Serialize to FriendlyByteBuf
            FriendlyByteBuf buf = new FriendlyByteBuf(Unpooled.buffer());
            message.writeToBuf(buf);
            
            LOGGER.debug("Generated server query with nonce: {}", state.serverNonce);
            return buf;
            
        } catch (Exception e) {
            LOGGER.error("Failed to generate server query", e);
            throw new RuntimeException("Failed to generate server query", e);
        }
    }
    
    /**
     * Validates a client response message.
     * Uses the echoed server nonce to find the matching pending authentication state.
     * Throws VerificationException on any failure - caller should disconnect immediately.
     * 
     * @param buf FriendlyByteBuf containing client response
     * @param expectedUsername The username from Minecraft's login flow (used for verification)
     * @throws VerificationException if verification fails
     */
    public static void validateClientResponse(
        FriendlyByteBuf buf,
        String expectedUsername
    ) throws VerificationException {
        try {
            // 1. Deserialize client response
            ClientResponseMessage response = ClientResponseMessage.fromBuf(buf);
            
            // 2. Retrieve stored auth state using the echoed server nonce
            CommonAuthState state = ServerAuthState.STATE.get(response.serverNonce);
            if (state == null) {
                throw new VerificationException("No pending authentication for server nonce: " + response.serverNonce);
            }
            
            if (state.isFinished()) {
                throw new VerificationException("Authentication already completed for server nonce: " + response.serverNonce);
            }
            
            // 3. Verify the echoed nonce matches (defense in depth)
            if (state.serverNonce != response.serverNonce) {
                throw new VerificationException("Server nonce mismatch in auth state");
            }
            
            // 4. Populate state with client data
            state.clientNonce = response.clientNonce;
            state.clientTemporaryKeys = new OptionalKeyPair();
            state.clientTemporaryKeys.publicKey = response.clientTempKey;
            
            // 5. Get verification codec
            if (!VerificationRegistry.isRegistered(response.verificationType)) {
                throw new VerificationException("Unknown verification type: " + response.verificationType);
            }
            
            VerificationCodec codec = VerificationRegistry.get(response.verificationType);
            
            // 6. Verify payload - throws VerificationException on failure
            VerificationResult result = codec.verify(response.encryptedPayload, state);
            
            if (!result.success) {
                throw new VerificationException("Verification failed: " + result.failureReason);
            }
            
            // 6.5. Verify authenticated username matches Minecraft's expected username
            if (!result.username.equals(expectedUsername)) {
                throw new VerificationException(
                    "Username mismatch: authenticated as '" + result.username + 
                    "' but connecting as '" + expectedUsername + "'"
                );
            }
            
            // 7. TOFU check - verify player's public key matches previously stored key
            java.util.Optional<java.security.PublicKey> storedKey = getStorage().getPlayerKey(result.playerUUID);
            if (storedKey.isPresent()) {
                // Player was seen before - verify it's the same key
                if (!storedKey.get().equals(result.clientPublicKey)) {
                    throw new VerificationException(
                        "Player public key mismatch for " + result.username + " (" + result.playerUUID + ")! " +
                        "This could indicate a compromised account or password change. " +
                        "Server admin must manually remove the old key to allow re-registration."
                    );
                }
                LOGGER.debug("Player key matches trusted key for {}", result.username);
            } else {
                // First time connecting - trust on first use
                getStorage().storePlayerKey(result.playerUUID, result.clientPublicKey);
                getStorage().save();
                LOGGER.info("Trusting new player: {} ({})", result.username, result.playerUUID);
            }
            
            // 8. Update state with verified data
            state.playerUUID = result.playerUUID;
            state.username = result.username;
            state.clientConstPublicKey = result.clientPublicKey;
            
            // 9. Convert to FinishedAuthState
            FinishedAuthState finished = new FinishedAuthState();
            finished.playerUUID = state.playerUUID;
            finished.username = state.username;
            finished.serverNonce = state.serverNonce;
            finished.clientNonce = state.clientNonce;
            finished.serverTemporaryKeys = state.serverTemporaryKeys;
            finished.clientTemporaryKeys = state.clientTemporaryKeys;
            finished.clientConstPublicKey = state.clientConstPublicKey;
            finished.serverConstPublicKey = state.serverConstPublicKey;
            
            // 10. Replace in-progress state with finished state
            ServerAuthState.STATE.put(response.serverNonce, finished);
            
            // 11. Mark player as authenticated for join verification
            ServerAuthState.markAuthenticated(result.username);
            
            LOGGER.info("Successfully authenticated player {} ({})", result.username, result.playerUUID);
            
        } catch (VerificationException e) {
            // Re-throw verification exceptions directly
            LOGGER.warn("Client authentication failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            // Wrap other exceptions
            LOGGER.error("Unexpected error during client validation", e);
            throw new VerificationException("Internal server error during authentication", e);
        }
    }
}
