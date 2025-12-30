package net.fivew14.authlogic.fabric.networking;

import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fivew14.authlogic.AuthLogic;
import net.fivew14.authlogic.client.ClientNetworking;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.FriendlyByteBuf;
import org.jetbrains.annotations.Nullable;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

public class FabricClientNetworking {
    public static void bootstrap() {
        ClientLoginNetworking.registerGlobalReceiver(AuthLogic.NETWORKING_CHANNEL_ID, FabricClientNetworking::handleClient);
    }

    private static CompletableFuture<@Nullable FriendlyByteBuf> handleClient(Minecraft minecraft, ClientHandshakePacketListenerImpl clientHandshakePacketListener, FriendlyByteBuf friendlyByteBuf, Consumer<GenericFutureListener<? extends Future<? super Void>>> genericFutureListenerConsumer) {
        return CompletableFuture.completedFuture(ClientNetworking.handleLoginQuery(friendlyByteBuf));
    }
}
