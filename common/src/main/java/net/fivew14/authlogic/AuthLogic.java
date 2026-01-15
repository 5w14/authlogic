package net.fivew14.authlogic;

import com.mojang.logging.LogUtils;
import dev.architectury.event.events.common.LifecycleEvent;
import dev.architectury.platform.Platform;
import dev.architectury.utils.Env;
import net.fivew14.authlogic.crypto.KeysProvider;
import net.fivew14.authlogic.server.AuthLogicDedicated;
import net.fivew14.authlogic.server.ServerNetworking;
import net.fivew14.authlogic.server.ServerStorage;
import net.fivew14.authlogic.verification.VerificationRegistry;
import net.fivew14.authlogic.verification.codecs.OfflineVerificationCodec;
import net.fivew14.authlogic.verification.codecs.OnlineVerificationCodec;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import org.slf4j.Logger;

/**
 * Main mod class for AuthLogic.
 * Handles initialization and registration of authentication system components.
 */
public final class AuthLogic {
    public static final String MOD_ID = "authlogic";
    public static final ResourceLocation NETWORKING_CHANNEL_ID = AuthLogic.id("authlogin");
    private static final Logger LOGGER = LogUtils.getLogger();

    private static ServerStorage serverStorage;
    private static boolean isIntegratedServer = false;

    /**
     * Initializes the mod.
     * Called by platform-specific loaders (Fabric/Forge).
     */
    public static void init() {
        LOGGER.info("Initializing AuthLogic");

        // Bootstrap crypto providers
        KeysProvider.bootstrap();

        // Register built-in verification codecs
        registerVerificationCodecs();

        // Initialize server storage on dedicated server
        // Client storage is initialized separately by AuthLogicClient.onClientInit()
        if (Platform.getEnvironment() == Env.SERVER) {
            initServerStorage();
            AuthLogicDedicated.onDedicatedStartup();
        } else {
            // On client, register for server starting event to handle integrated servers
            LifecycleEvent.SERVER_STARTING.register(AuthLogic::onServerStarting);
            LifecycleEvent.SERVER_STOPPED.register(AuthLogic::onServerStopped);
        }

        LOGGER.info("AuthLogic initialized successfully with {} verification codecs",
                VerificationRegistry.getRegisteredTypes().size());
    }

    /**
     * Called when a server is starting (including integrated servers).
     */
    private static void onServerStarting(MinecraftServer server) {
        if (server.isSingleplayer()) {
            LOGGER.info("Integrated server starting - authentication disabled for local connections");
            isIntegratedServer = true;
            // Still initialize storage in case it's opened to LAN
            initServerStorage();
        }
    }

    /**
     * Called when a server stops.
     */
    private static void onServerStopped(MinecraftServer server) {
        if (isIntegratedServer) {
            LOGGER.info("Integrated server stopped");
            isIntegratedServer = false;
            serverStorage = null;
        }
    }

    /**
     * Registers built-in verification codecs.
     */
    private static void registerVerificationCodecs() {
        // Register offline mode codec
        VerificationRegistry.register(
                new ResourceLocation(MOD_ID, "offline"),
                new OfflineVerificationCodec()
        );

        // Register online mode codec
        VerificationRegistry.register(
                new ResourceLocation(MOD_ID, "online"),
                new OnlineVerificationCodec()
        );

        LOGGER.info("Registered verification codecs: offline, online");
    }

    /**
     * Initializes server-side storage.
     */
    private static void initServerStorage() {
        try {
            serverStorage = new ServerStorage();
            serverStorage.load();
            ServerNetworking.setStorage(serverStorage);
            LOGGER.info("Server storage initialized");
        } catch (Exception e) {
            LOGGER.error("Failed to initialize server storage", e);
            throw new RuntimeException("Failed to initialize server storage", e);
        }
    }

    /**
     * Gets the server storage instance.
     *
     * @return Server storage
     * @throws IllegalStateException if called on client or not initialized
     */
    public static ServerStorage getServerStorage() {
        if (serverStorage == null) {
            throw new IllegalStateException("Server storage not initialized or running on client");
        }
        return serverStorage;
    }

    public static boolean isOnDedicated() {
        return AuthLogicDedicated.isRunningDedicated();
    }

    /**
     * Checks if an integrated (singleplayer) server is currently running.
     *
     * @return true if an integrated server is active
     */
    public static boolean isIntegratedServer() {
        return isIntegratedServer;
    }

    public static ResourceLocation id(String location) {
        return new ResourceLocation(MOD_ID, location);
    }
}
