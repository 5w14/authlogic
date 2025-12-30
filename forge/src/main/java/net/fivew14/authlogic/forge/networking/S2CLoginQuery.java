package net.fivew14.authlogic.forge.networking;

import net.fivew14.authlogic.client.ClientNetworking;
import net.fivew14.authlogic.server.ServerNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.simple.SimpleChannel;

import java.util.function.Supplier;

public final class S2CLoginQuery {
    private static SimpleChannel CHANNEL;

    private int loginIndex;

    FriendlyByteBuf buffer;

    public S2CLoginQuery(int loginIndex) {
        this.loginIndex = loginIndex;
        this.buffer = ServerNetworking.getServerQuery();
    }

    public static void register(SimpleChannel channel, int packetId) {
        S2CLoginQuery.CHANNEL = channel;
        channel.messageBuilder(S2CLoginQuery.class, packetId, NetworkDirection.LOGIN_TO_CLIENT)
                .loginIndex(S2CLoginQuery::loginIndex, S2CLoginQuery::setLoginIndex)
                .decoder(S2CLoginQuery::decode).encoder(S2CLoginQuery::encode)
                .consumerNetworkThread(S2CLoginQuery::handle).markAsLoginPacket().add();
    }

    private void encode(FriendlyByteBuf friendlyByteBuf) {
        friendlyByteBuf.writeBytes(this.buffer);
    }

    private static S2CLoginQuery decode(FriendlyByteBuf friendlyByteBuf) {
        S2CLoginQuery pkt = new S2CLoginQuery(-1);
        pkt.buffer = friendlyByteBuf;
        return pkt;
    }

    private boolean handle(Supplier<NetworkEvent.Context> ctx) {
        var response = ClientNetworking.handleLoginQuery(this.buffer);
        ctx.get().setPacketHandled(true);
        CHANNEL.sendToServer(new C2SQueryResponse(this.loginIndex, response));
        return true;
    }

    public int loginIndex() { return loginIndex; }
    public void setLoginIndex(int loginIndex) { this.loginIndex = loginIndex; }
}
