package net.fivew14.authlogic.client;

import com.mojang.logging.LogUtils;
import dev.architectury.event.events.client.ClientLifecycleEvent;
import net.fivew14.authlogic.client.ClientNetworking.MojangCertificateData;
import net.fivew14.authlogic.client.screen.SetupMultiplayerPasswordScreen;
import net.fivew14.authlogic.verification.VerificationException;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.FriendlyByteBuf;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Optional;

public class AuthLogicClient {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static ClientStorage clientStorage;
    private static boolean onlineMode = false;
    private static Optional<MojangCertificateData> cachedCertificate = Optional.empty();

    public static void onClientInit() {
        LOGGER.info("Initializing AuthLogic client");
        
        // Initialize client storage
        clientStorage = new ClientStorage();
        try {
            clientStorage.load();
            LOGGER.info("Client storage loaded successfully");
        } catch (IOException e) {
            LOGGER.error("Failed to load client storage", e);
        }
        
        // Set storage for networking and auth handler
        ClientNetworking.setStorage(clientStorage);
        ClientAuthHandler.setStorage(clientStorage);

        ClientLifecycleEvent.CLIENT_STARTED.register(AuthLogicClient::onClientStarted);

        if (Minecraft.getInstance().getProfileKeyPairManager() != null) {
            onClientStarted(Minecraft.getInstance());
        }
    }

    static boolean hasStartedSetup;
    private static void onClientStarted(Minecraft minecraft) {
        if (hasStartedSetup) return;
        hasStartedSetup = true;

        LOGGER.info("Client started, checking profile key pair");
        minecraft.getProfileKeyPairManager().prepareKeyPair().whenComplete((keyPairOpt, e) -> {
            if (e != null || keyPairOpt.isEmpty()) {
                LOGGER.info("Client is in offline mode (no profile key pair available)");
                onlineMode = false;
                cachedCertificate = Optional.empty();
            } else {
                LOGGER.info("Client is in online mode (profile key pair available)");
                onlineMode = true;
                
                // Cache the certificate data including private key
                var keyPair = keyPairOpt.get();
                var publicKeyData = keyPair.publicKey().data();
                cachedCertificate = Optional.of(MojangCertificateData.of(
                    publicKeyData.key(),
                    keyPair.privateKey(),
                    publicKeyData.keySignature(),
                    publicKeyData.expiresAt().toEpochMilli()
                ));
                LOGGER.debug("Cached Mojang certificate, expires at: {}", publicKeyData.expiresAt());
            }
        });
    }
    
    /**
     * Gets the client storage instance.
     * 
     * @return Client storage
     */
    public static ClientStorage getStorage() {
        return clientStorage;
    }
    
    /**
     * Checks if the client is in online mode (has a valid Mojang profile key pair).
     * 
     * @return true if in online mode
     */
    public static boolean isOnlineMode() {
        return onlineMode;
    }
    
    /**
     * Gets the cached Mojang certificate data.
     * This is populated during client startup if online mode is available.
     * 
     * @return Optional certificate data
     */
    public static Optional<MojangCertificateData> getMojangCertificate() {
        return cachedCertificate;
    }
    
    /**
     * Refreshes the Mojang certificate from the ProfileKeyPairManager.
     * Call this if the certificate may have expired or needs updating.
     * 
     * @param minecraft Minecraft instance
     */
    public static void refreshCertificate(Minecraft minecraft) {
        var freshCert = ClientNetworking.getMojangCertificateData(minecraft);
        if (freshCert.isPresent()) {
            cachedCertificate = freshCert;
            onlineMode = true;
            LOGGER.debug("Refreshed Mojang certificate");
        } else {
            cachedCertificate = Optional.empty();
            onlineMode = false;
            LOGGER.warn("Failed to refresh Mojang certificate, falling back to offline mode");
        }
    }
    
    /**
     * Handles a server authentication challenge and generates a response.
     * This is the common entry point for both Fabric and Forge client-side handling.
     * 
     * @param challengeBuf Buffer containing the server challenge
     * @param serverAddress Server address for password hash lookup
     * @return Response buffer to send back to the server
     * @throws VerificationException if authentication fails
     */
    public static FriendlyByteBuf handleServerChallenge(
            FriendlyByteBuf challengeBuf,
            String serverAddress
    ) throws VerificationException {
        Minecraft minecraft = Minecraft.getInstance();
        var profile = minecraft.getUser().getGameProfile();
        var uuid = profile.getId();
        String username = profile.getName();
        
        boolean useOnlineMode = isOnlineMode();
        Optional<MojangCertificateData> mojangCert = getMojangCertificate();
        
        if (useOnlineMode && mojangCert.isEmpty()) {
            LOGGER.warn("Online mode but no Mojang certificate available, falling back to offline mode");
            useOnlineMode = false;
        }
        
        // Password hash is only needed for offline mode
        // Online mode uses Mojang certificate keys instead
        String passwordHash = null;
        if (!useOnlineMode) {
            passwordHash = ClientAuthHandler.getPasswordHash(serverAddress);
        }
        
        FriendlyByteBuf response = ClientNetworking.handleLoginQuery(
            challengeBuf,
            serverAddress,
            uuid,
            username,
            useOnlineMode,
            passwordHash,
            mojangCert
        );
        
        LOGGER.info("Successfully generated authentication response for {}", serverAddress);
        return response;
    }

    public static boolean openSetupMultiplayerScreen(Screen returnTo) {
        if (getStorage().hasPasswordSaved() || isOnlineMode())
            return false;

        Minecraft.getInstance().setScreen(new SetupMultiplayerPasswordScreen(returnTo));
        return true;
    }
}
