package net.fivew14.authlogic.fabric.networking;


import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.fivew14.authlogic.AuthLogic;
import net.fivew14.authlogic.server.ServerNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FabricServerNetworking {
    private static final Logger log = LoggerFactory.getLogger(FabricServerNetworking.class);

    public static void bootstrap() {
        ServerLoginNetworking.registerGlobalReceiver(AuthLogic.NETWORKING_CHANNEL_ID, FabricServerNetworking::handleServer);
        ServerLoginConnectionEvents.QUERY_START.register(FabricServerNetworking::sendQueryToClient);
    }

    private static void sendQueryToClient(ServerLoginPacketListenerImpl serverLoginPacketListener, MinecraftServer server, PacketSender packetSender, ServerLoginNetworking.LoginSynchronizer loginSynchronizer) {
        packetSender.sendPacket(AuthLogic.NETWORKING_CHANNEL_ID, ServerNetworking.getServerQuery());
    }

    private static void handleServer(MinecraftServer server, ServerLoginPacketListenerImpl serverLoginPacketListener, boolean b, FriendlyByteBuf friendlyByteBuf, ServerLoginNetworking.LoginSynchronizer loginSynchronizer, PacketSender packetSender) {
        ServerNetworking.validateClientResponse(friendlyByteBuf, serverLoginPacketListener::getUserName);
    }
}
