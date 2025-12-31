package net.fivew14.authlogic.client;

import com.mojang.logging.LogUtils;
import io.netty.buffer.Unpooled;
import net.fivew14.authlogic.crypto.Hasher;
import net.fivew14.authlogic.crypto.KeysProvider;
import net.fivew14.authlogic.crypto.OptionalKeyPair;
import net.fivew14.authlogic.protocol.ClientResponseMessage;
import net.fivew14.authlogic.protocol.ServerChallengeMessage;
import net.fivew14.authlogic.server.state.CommonAuthState;
import net.fivew14.authlogic.verification.OfflineVerificationPayload;
import net.fivew14.authlogic.verification.OnlineVerificationPayload;
import net.fivew14.authlogic.verification.VerificationCodec;
import net.fivew14.authlogic.verification.VerificationException;
import net.fivew14.authlogic.verification.VerificationRegistry;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.world.entity.player.ProfileKeyPair;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Client-side networking for authentication protocol.
 * Handles server challenge validation and response generation.
 */
public class ClientNetworking {
    
    /**
     * Container for Mojang player certificate data required for online mode authentication.
     * This data is obtained from Minecraft's ProfileKeyPairManager.
     */
    public record MojangCertificateData(
        PublicKey publicKey,           // Player's RSA public key from Mojang
        byte[] keySignature,           // Mojang's signature on the public key
        long expiresAtMillis           // Expiration timestamp in milliseconds
    ) {
        /**
         * Creates certificate data from Minecraft's ProfileKeyPair.
         * This method should be called by platform-specific code (Fabric/Forge).
         * 
         * @param publicKey RSA public key
         * @param keySignature Mojang's signature
         * @param expiresAt Expiration timestamp
         * @return Certificate data
         */
        public static MojangCertificateData of(PublicKey publicKey, byte[] keySignature, long expiresAt) {
            return new MojangCertificateData(publicKey, keySignature, expiresAt);
        }
        
        /**
         * Checks if the certificate is still valid (not expired).
         * 
         * @return true if valid
         */
        public boolean isValid() {
            return System.currentTimeMillis() < expiresAtMillis;
        }
    }
    private static final Logger LOGGER = LogUtils.getLogger();
    private static ClientStorage storage;
    
    /**
     * Sets the client storage instance.
     * Must be called during initialization.
     * 
     * @param clientStorage Client storage instance
     */
    public static void setStorage(ClientStorage clientStorage) {
        storage = clientStorage;
    }
    
    /**
     * Gets the client storage instance.
     * 
     * @return Client storage
     * @throws IllegalStateException if storage not initialized
     */
    private static ClientStorage getStorage() {
        if (storage == null) {
            throw new IllegalStateException("ClientStorage not initialized. Call setStorage() first.");
        }
        return storage;
    }
    
    /**
     * Gets Mojang certificate data from the ProfileKeyPairManager.
     * This is a common utility used by both Fabric and Forge.
     * 
     * @param minecraft Minecraft instance
     * @return Optional certificate data, empty if unavailable
     */
    public static Optional<MojangCertificateData> getMojangCertificateData(Minecraft minecraft) {
        try {
            var keyPairManager = minecraft.getProfileKeyPairManager();
            if (keyPairManager == null) {
                LOGGER.warn("ProfileKeyPairManager is null");
                return Optional.empty();
            }
            
            // Try to get the current key pair (may trigger refresh if needed)
            Optional<ProfileKeyPair> keyPairOpt = keyPairManager.prepareKeyPair()
                .join(); // Block to get the result
            
            if (keyPairOpt.isEmpty()) {
                LOGGER.warn("No ProfileKeyPair available from ProfileKeyPairManager");
                return Optional.empty();
            }
            
            ProfileKeyPair keyPair = keyPairOpt.get();
            
            // Check if key pair needs refresh
            if (keyPair.dueRefresh()) {
                LOGGER.warn("ProfileKeyPair is due for refresh, attempting to use it anyway");
            }
            
            // Extract data from the profile public key
            var publicKeyData = keyPair.publicKey().data();
            
            MojangCertificateData certData = MojangCertificateData.of(
                publicKeyData.key(),
                publicKeyData.keySignature(),
                publicKeyData.expiresAt().toEpochMilli()
            );
            
            LOGGER.debug("Retrieved Mojang certificate, expires at: {}", publicKeyData.expiresAt());
            return Optional.of(certData);
            
        } catch (Exception e) {
            LOGGER.error("Failed to get Mojang certificate data", e);
            return Optional.empty();
        }
    }
    
    /**
     * Handles a login query from the server.
     * Validates server challenge and generates encrypted response.
     * 
     * SECURITY: Password should be hashed immediately by caller before passing to this method.
     * 
     * @param buf FriendlyByteBuf containing server challenge
     * @param serverAddress Server address (IP:port or hostname)
     * @param clientUUID Client's UUID
     * @param username Client's username
     * @param onlineMode true for online mode, false for offline
     * @param passwordHash SHA-256 hash of user's password (NOT plain password)
     * @param mojangCertificate Optional Mojang certificate data for online mode (required if onlineMode=true)
     * @return FriendlyByteBuf containing client respons4
     * @throws VerificationException if validation fails
     */
    public static FriendlyByteBuf handleLoginQuery(
        FriendlyByteBuf buf,
        String serverAddress,
        UUID clientUUID,
        String username,
        boolean onlineMode,
        String passwordHash,
        Optional<MojangCertificateData> mojangCertificate
    ) throws VerificationException {
        try {
            // Validate that we received a hash, not a plain password
            if (passwordHash == null || passwordHash.length() != 64) {
                throw new VerificationException(
                    "Password must be pre-hashed using ClientStorage.hashPassword()",
                    Component.translatable("authlogic.error.password_not_hashed")
                );
            }
            
            // 1. Deserialize server challenge
            ServerChallengeMessage challenge = ServerChallengeMessage.fromBuf(buf);
            
            // 2. Verify server signature
            if (!challenge.verify()) {
                throw new VerificationException(
                    "Invalid server signature - server authentication failed!",
                    Component.translatable("authlogic.error.server_signature_invalid.title")
                        .withStyle(ChatFormatting.RED, ChatFormatting.BOLD)
                        .append(Component.literal("\n\n"))
                        .append(Component.translatable("authlogic.error.server_signature_invalid")
                            .withStyle(ChatFormatting.RESET))
                );
            }
            
            LOGGER.debug("Server challenge signature verified");
            
            // 3. Check if server is trusted (TOFU - Trust On First Use)
            Optional<PublicKey> trustedKey = getStorage().getServerKey(serverAddress);
            if (trustedKey.isPresent()) {
                // Server was seen before - verify it's the same key
                if (!trustedKey.get().equals(challenge.serverPublicKey)) {
                    String expectedHash = Base64.getEncoder().encodeToString(
                        Hasher.sha256(trustedKey.get().getEncoded())).substring(0, 16) + "...";
                    String receivedHash = Base64.getEncoder().encodeToString(
                        Hasher.sha256(challenge.serverPublicKey.getEncoded())).substring(0, 16) + "...";
                    
                    throw new VerificationException(
                        "Server public key mismatch! Possible MITM attack.",
                        Component.translatable("authlogic.error.server_key_mismatch.title")
                            .withStyle(ChatFormatting.RED, ChatFormatting.BOLD)
                            .append(Component.literal("\n\n"))
                            .append(Component.translatable("authlogic.error.server_key_mismatch")
                                .withStyle(ChatFormatting.RESET, ChatFormatting.YELLOW))
                            .append(Component.literal("\n\n"))
                            .append(Component.translatable("authlogic.error.server_key_mismatch.detail")
                                .withStyle(ChatFormatting.RESET, ChatFormatting.GRAY))
                            .append(Component.literal("\n\n"))
                            .append(Component.translatable("authlogic.error.server_key_mismatch.expected", expectedHash)
                                .withStyle(ChatFormatting.RESET))
                            .append(Component.literal("\n"))
                            .append(Component.translatable("authlogic.error.server_key_mismatch.received", receivedHash)
                                .withStyle(ChatFormatting.RESET))
                    );
                }
                LOGGER.debug("Server key matches trusted key");
            } else {
                // First time connecting - trust on first use
                getStorage().trustServer(serverAddress, challenge.serverPublicKey);
                getStorage().save();
                LOGGER.info("Trusting new server: {}", serverAddress);
            }
            
            // 4. Derive client keypair from password hash (not plain password)
            getStorage().deriveClientKeys(passwordHash, challenge.serverPublicKey);
            KeyPair clientKeys = getStorage().getClientKeyPair();
            
            // 5. Generate client temp keypair and nonce
            KeyPair clientTempKeys = KeysProvider.generateTemporaryKeyPair();
            long clientNonce = KeysProvider.generateNonce();
            
            // 6. Create auth state for encryption
            CommonAuthState state = new CommonAuthState() {
                @Override public boolean isAuthenticated() { return false; }
                @Override public boolean isFinished() { return false; }
            };
            state.serverTemporaryKeys = new OptionalKeyPair();
            state.serverTemporaryKeys.publicKey = challenge.serverTempKey;
            state.clientTemporaryKeys = OptionalKeyPair.of(clientTempKeys);
            state.serverNonce = challenge.serverNonce;
            state.clientNonce = clientNonce;
            
            // 7. Create payload based on mode
            Object payload;
            ResourceLocation verificationType;

            if (onlineMode) {
                // Validate Mojang certificate is present and valid
                if (mojangCertificate.isEmpty()) {
                    throw new VerificationException(
                        "Online mode requires Mojang player certificate",
                        Component.translatable("authlogic.error.mojang_certificate_missing.title")
                            .withStyle(ChatFormatting.RED, ChatFormatting.BOLD)
                            .append(Component.literal("\n\n"))
                            .append(Component.translatable("authlogic.error.mojang_certificate_missing")
                                .withStyle(ChatFormatting.RESET))
                            .append(Component.literal("\n"))
                            .append(Component.translatable("authlogic.error.mojang_certificate_missing.detail")
                                .withStyle(ChatFormatting.GRAY))
                    );
                }

                MojangCertificateData certData = mojangCertificate.get();

                if (!certData.isValid()) {
                    throw new VerificationException(
                        "Mojang player certificate has expired",
                        Component.translatable("authlogic.error.mojang_certificate_expired.title")
                            .withStyle(ChatFormatting.RED, ChatFormatting.BOLD)
                            .append(Component.literal("\n\n"))
                            .append(Component.translatable("authlogic.error.mojang_certificate_expired")
                                .withStyle(ChatFormatting.RESET))
                            .append(Component.literal("\n"))
                            .append(Component.translatable("authlogic.error.mojang_certificate_expired.detail")
                                .withStyle(ChatFormatting.GRAY))
                    );
                }

                LOGGER.debug("Using Mojang certificate for online mode authentication");
                
                OnlineVerificationPayload online = OnlineVerificationPayload.create(
                    clientUUID,
                    username,
                    certData.publicKey,  // Use Mojang-signed public key
                    clientKeys.getPrivate(),
                    certData.expiresAtMillis,
                    certData.keySignature,  // Use actual Mojang signature
                    challenge.serverTempKey,
                    clientTempKeys.getPublic(),
                    challenge.serverNonce,
                    clientNonce
                );
                payload = online;
                verificationType = new ResourceLocation("authlogic", "online");
            } else {
                OfflineVerificationPayload offline = OfflineVerificationPayload.create(
                    clientUUID,
                    username,
                    clientKeys.getPublic(),
                    clientKeys.getPrivate(),
                    challenge.serverTempKey,
                    clientTempKeys.getPublic(),
                    challenge.serverNonce,
                    clientNonce
                );
                payload = offline;
                verificationType = new ResourceLocation("authlogic", "offline");
            }
            
            // 8. Encrypt payload
            if (!VerificationRegistry.isRegistered(verificationType)) {
                throw new VerificationException(
                    "Verification type not registered: " + verificationType,
                    Component.translatable("authlogic.error.verification_type_not_registered", verificationType.toString())
                );
            }
            
            VerificationCodec codec = VerificationRegistry.get(verificationType);
            byte[] encryptedPayload = codec.encode(payload, state);
            
            // 9. Create response message (echo server nonce for correlation)
            ClientResponseMessage response = ClientResponseMessage.create(
                verificationType,
                challenge.serverNonce,  // Echo server nonce for protocol-level correlation
                clientNonce,
                clientTempKeys.getPublic(),
                encryptedPayload
            );
            
            // 10. Serialize to FriendlyByteBuf
            FriendlyByteBuf responseBuf = new FriendlyByteBuf(Unpooled.buffer());
            response.writeToBuf(responseBuf);
            
            LOGGER.info("Generated client response for {} mode", onlineMode ? "online" : "offline");
            return responseBuf;
            
        } catch (VerificationException e) {
            LOGGER.error("Authentication failed: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            LOGGER.error("Unexpected error during login query handling", e);
            throw new VerificationException("Internal client error during authentication", e);
        }
    }
}
