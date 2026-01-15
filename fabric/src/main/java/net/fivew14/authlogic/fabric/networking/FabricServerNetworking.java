package net.fivew14.authlogic.fabric.networking;


import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import io.netty.buffer.Unpooled;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.fivew14.authlogic.AuthLogic;
import net.fivew14.authlogic.mixin.ServerLoginPacketListenerImplAccessor;
import net.fivew14.authlogic.server.ServerNetworking;
import net.fivew14.authlogic.verification.VerificationException;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.slf4j.Logger;

import java.util.concurrent.CompletableFuture;

/**
 * Fabric server-side networking for AuthLogic authentication.
 * <p>
 * Authentication state correlation is handled at the protocol level using
 * the server nonce, so no connection ID management is needed here.
 */
public class FabricServerNetworking {
    private static final Logger LOGGER = LogUtils.getLogger();

    public static void bootstrap() {
        ServerLoginNetworking.registerGlobalReceiver(AuthLogic.NETWORKING_CHANNEL_ID, FabricServerNetworking::handleServer);
        ServerLoginConnectionEvents.QUERY_START.register(FabricServerNetworking::sendQueryToClient);
    }

    private static void sendQueryToClient(
            ServerLoginPacketListenerImpl handler,
            MinecraftServer server,
            PacketSender packetSender,
            ServerLoginNetworking.LoginSynchronizer loginSynchronizer
    ) {
        // No need for verification for singleplayer/integrated servers.
        if (server.isSingleplayer() || AuthLogic.isIntegratedServer()) {
            LOGGER.debug("Skipping authentication query for singleplayer/integrated server");
            return;
        }

        try {
            // Server nonce is used for correlation - no connection ID needed
            FriendlyByteBuf query = ServerNetworking.getServerQuery();
            packetSender.sendPacket(AuthLogic.NETWORKING_CHANNEL_ID, query);
            LOGGER.debug("Sent authentication query to client");
        } catch (Exception e) {
            LOGGER.error("Failed to send authentication query", e);
            handler.disconnect(Component.literal("Authentication error: " + e.getMessage()));
        }
    }

    private static void handleServer(
            MinecraftServer server,
            ServerLoginPacketListenerImpl handler,
            boolean understood,
            FriendlyByteBuf buf,
            ServerLoginNetworking.LoginSynchronizer synchronizer,
            PacketSender packetSender
    ) {
        if (!understood) {
            LOGGER.warn("Client did not understand authentication query");
            handler.disconnect(Component.literal("Client does not support AuthLogic authentication"));
            return;
        }

        // CRITICAL: Copy the buffer before async use - Netty will release the original
        // buffer after this handler returns, but we need the data in the async task
        byte[] responseData = new byte[buf.readableBytes()];
        buf.readBytes(responseData);

        // Get username now on the Netty thread (before async)
        GameProfile profile = ((ServerLoginPacketListenerImplAccessor) handler).authlogic$getGameProfile();
        String expectedUsername = profile != null ? profile.getName() : "unknown";

        // Use synchronizer.waitFor() to block login until authentication completes.
        // This is critical because validateClientResponse() may make blocking HTTP calls
        // to Mojang's API for online mode verification, which would otherwise complete
        // AFTER the player join event fires, causing a race condition.
        synchronizer.waitFor(CompletableFuture.runAsync(() -> {
            // Reconstruct buffer from copied data
            FriendlyByteBuf bufCopy = new FriendlyByteBuf(Unpooled.wrappedBuffer(responseData));

            try {
                ServerNetworking.validateClientResponse(bufCopy, expectedUsername);
                LOGGER.debug("Client authenticated successfully: {}", expectedUsername);
            } catch (VerificationException e) {
                LOGGER.error("Client authentication failed: {}", e.getMessage());
                handler.disconnect(Component.literal("Authentication failed: " + e.getMessage()));
            } catch (Exception e) {
                LOGGER.error("Unexpected error during authentication", e);
                handler.disconnect(Component.literal("Authentication error: " + e.getMessage()));
            } finally {
                bufCopy.release();
            }
        }));
    }
}
