package net.fivew14.authlogic.forge.networking;

import com.mojang.authlib.GameProfile;
import com.mojang.logging.LogUtils;
import net.fivew14.authlogic.mixin.ServerLoginPacketListenerImplAccessor;
import net.fivew14.authlogic.server.ServerNetworking;
import net.fivew14.authlogic.verification.VerificationException;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import net.minecraftforge.network.HandshakeHandler;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.simple.SimpleChannel;
import org.slf4j.Logger;

import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * Forge server-side handler for client authentication responses.
 * <p>
 * Authentication state correlation is handled at the protocol level using
 * the server nonce echoed in the client response, so no connection ID
 * management is needed here.
 */
public final class C2SQueryResponse implements IntSupplier {
    private static final Logger LOGGER = LogUtils.getLogger();

    public static void register(SimpleChannel channel, int packetId) {
        channel.messageBuilder(C2SQueryResponse.class, packetId, NetworkDirection.LOGIN_TO_SERVER)
                .encoder(C2SQueryResponse::encode).decoder(C2SQueryResponse::decode)
                .consumerNetworkThread(HandshakeHandler.indexFirst(C2SQueryResponse::handle))
                .loginIndex(C2SQueryResponse::getLoginIndex, C2SQueryResponse::setLoginIndex)
                .add();
    }

    private int loginIndex; // injected
    private final FriendlyByteBuf payload;

    public C2SQueryResponse(FriendlyByteBuf payload) {
        this.payload = payload;
    }

    /**
     * Checks if this is an empty/skip response (for local connections).
     */
    public boolean isEmpty() {
        return payload == null || payload.readableBytes() == 0;
    }

    public int getLoginIndex() {
        return loginIndex;
    }

    public void setLoginIndex(int loginIndex) {
        this.loginIndex = loginIndex;
    }

    public static void encode(C2SQueryResponse msg, FriendlyByteBuf buf) {
        if (msg.isEmpty()) {
            buf.writeVarInt(0); // Empty payload marker
        } else {
            buf.writeVarInt(msg.payload.readableBytes());
            buf.writeBytes(msg.payload, msg.payload.readerIndex(), msg.payload.readableBytes());
        }
    }

    public static C2SQueryResponse decode(FriendlyByteBuf buf) {
        int len = buf.readVarInt();
        if (len == 0) {
            return new C2SQueryResponse(null); // Empty/skip response
        }
        FriendlyByteBuf payload = new FriendlyByteBuf(buf.readBytes(len));
        return new C2SQueryResponse(payload);
    }

    public static void handle(HandshakeHandler h, C2SQueryResponse msg, Supplier<NetworkEvent.Context> ctx) {
        LOGGER.debug("C2SQueryResponse.handle() called, isEmpty={}", msg.isEmpty());
        var networkManager = ctx.get().getNetworkManager();

        // Skip authentication for empty responses (local/integrated server)
        if (msg.isEmpty()) {
            LOGGER.debug("Received empty auth response, skipping authentication (local connection)");
            ctx.get().setPacketHandled(true);
            return;
        }

        try {
            // Get the expected username from Minecraft's login handler game profile via mixin accessor
            String expectedUsername = "unknown";
            if (networkManager.getPacketListener() instanceof ServerLoginPacketListenerImpl loginHandler) {
                GameProfile profile = ((ServerLoginPacketListenerImplAccessor) loginHandler).authlogic$getGameProfile();
                if (profile != null) {
                    expectedUsername = profile.getName();
                }
            }

            LOGGER.debug("Validating client response for expected username: {}", expectedUsername);

            // Validate client response - correlation is by server nonce in the response
            ServerNetworking.validateClientResponse(msg.payload, expectedUsername);

            LOGGER.debug("Client authenticated successfully: {}", expectedUsername);
            ctx.get().setPacketHandled(true);

        } catch (VerificationException e) {
            LOGGER.error("Client authentication failed: {}", e.getMessage());
            networkManager.disconnect(Component.literal("Authentication failed: " + e.getMessage()));
            ctx.get().setPacketHandled(false);
        } catch (Exception e) {
            LOGGER.error("Unexpected error during authentication", e);
            networkManager.disconnect(Component.literal("Authentication error: " + e.getMessage()));
            ctx.get().setPacketHandled(false);
        }
    }

    @Override
    public int getAsInt() {
        return this.loginIndex;
    }
}
