package net.fivew14.authlogic.fabric.networking;

import com.mojang.logging.LogUtils;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fivew14.authlogic.AuthLogic;
import net.fivew14.authlogic.client.AuthLogicClient;
import net.fivew14.authlogic.mixin.ClientHandshakeAccessor;
import net.fivew14.authlogic.verification.VerificationException;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.FriendlyByteBuf;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Fabric client-side networking for AuthLogic authentication.
 * Handles server challenges and generates authentication responses.
 */
public class FabricClientNetworking {
    private static final Logger LOGGER = LogUtils.getLogger();

    public static void bootstrap() {
        ClientLoginNetworking.registerGlobalReceiver(AuthLogic.NETWORKING_CHANNEL_ID, FabricClientNetworking::handleClient);
    }

    private static CompletableFuture<@Nullable FriendlyByteBuf> handleClient(
            Minecraft minecraft,
            ClientHandshakePacketListenerImpl handler,
            FriendlyByteBuf buf,
            Consumer<GenericFutureListener<? extends Future<? super Void>>> consumer
    ) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String serverAddress = getServerAddress(handler);
                return AuthLogicClient.handleServerChallenge(buf, serverAddress);
            } catch (VerificationException e) {
                LOGGER.error("Authentication failed: {}", e.getMessage());
                ((ClientHandshakeAccessor) handler).authlogic$getConnection().disconnect(e.getVisualError());
                return null;
            } catch (Exception e) {
                LOGGER.error("Unexpected error during authentication", e);
                return null;
            }
        });
    }

    /**
     * Extracts server address from the connection.
     *
     * @return Server address (IP:port or hostname)
     */
    private static String getServerAddress(ClientHandshakePacketListenerImpl handshake) {
        try {
            // Try to get server info from Minecraft instance
            var serverData = ((ClientHandshakeAccessor) handshake).authlogic$getServerData();

            if (serverData == null)
                serverData = Minecraft.getInstance().getCurrentServer();
            if (serverData != null)
                return serverData.ip;

            var address = ((ClientHandshakeAccessor) handshake).authlogic$getConnection().getRemoteAddress();
            return address.toString();
        } catch (Exception e) {
            LOGGER.warn("Could not determine server address, using default", e);
            return "unknown";
        }
    }
}
