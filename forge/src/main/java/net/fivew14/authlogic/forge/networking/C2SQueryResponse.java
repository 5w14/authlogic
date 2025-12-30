package net.fivew14.authlogic.forge.networking;

import net.fivew14.authlogic.server.ServerNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.simple.SimpleChannel;

import java.util.function.Supplier;

public final class C2SQueryResponse {
    private static SimpleChannel CHANNEL;

    private int loginIndex;

    FriendlyByteBuf buffer;

    public C2SQueryResponse(int loginIndex, FriendlyByteBuf buffer) {
        this.loginIndex = loginIndex;
        this.buffer = buffer;
    }

    public static void register(SimpleChannel channel, int packetId) {
        C2SQueryResponse.CHANNEL = channel;
        channel.messageBuilder(C2SQueryResponse.class, packetId, NetworkDirection.LOGIN_TO_SERVER)
                .loginIndex(C2SQueryResponse::loginIndex, C2SQueryResponse::setLoginIndex)
                .decoder(C2SQueryResponse::decode).encoder(C2SQueryResponse::encode)
                .consumerNetworkThread(C2SQueryResponse::handle).markAsLoginPacket().add();
    }

    private void encode(FriendlyByteBuf friendlyByteBuf) {
    }

    private static C2SQueryResponse decode(FriendlyByteBuf friendlyByteBuf) {
        return new C2SQueryResponse(-1, friendlyByteBuf);
    }

    private boolean handle(Supplier<NetworkEvent.Context> ctx) {
        ServerNetworking.validateClientResponse(this.buffer, () -> ctx.get().getSender().getGameProfile().getName());
        ctx.get().setPacketHandled(true);
        return true;
    }

    public int loginIndex() { return loginIndex; }
    public void setLoginIndex(int loginIndex) { this.loginIndex = loginIndex; }
}
