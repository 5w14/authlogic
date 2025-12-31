package net.fivew14.authlogic.forge.networking;

import com.mojang.logging.LogUtils;
import net.fivew14.authlogic.AuthLogic;
import net.fivew14.authlogic.client.AuthLogicClient;
import net.fivew14.authlogic.server.ServerNetworking;
import net.fivew14.authlogic.verification.VerificationException;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraftforge.network.HandshakeHandler;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.simple.SimpleChannel;
import org.slf4j.Logger;

import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

import org.apache.commons.lang3.tuple.Pair;

/**
 * Forge client-side handler for server authentication queries.
 * 
 * Authentication state correlation is handled at the protocol level using
 * the server nonce, which is echoed in the client response.
 */
public final class S2CLoginQuery implements IntSupplier {
    private static final Logger LOGGER = LogUtils.getLogger();
    
    public static void register(SimpleChannel channel, int packetId) {
        channel.messageBuilder(S2CLoginQuery.class, packetId, NetworkDirection.LOGIN_TO_CLIENT)
                .encoder(S2CLoginQuery::encode).decoder(S2CLoginQuery::decode)
                .consumerNetworkThread(HandshakeHandler.biConsumerFor(S2CLoginQuery::handle))
                .loginIndex(S2CLoginQuery::getLoginIndex, S2CLoginQuery::setLoginIndex)
                .buildLoginPacketList(S2CLoginQuery::buildServerQuery)
                .markAsLoginPacket().add();
    }

    private int loginIndex; // injected
    private FriendlyByteBuf payload; // populated by decode() on client side

    // No-argument constructor - used by server (encode generates payload) and Forge reflection
    public S2CLoginQuery() {
        this.payload = null;
    }

    // Constructor used by decode() on client side
    private S2CLoginQuery(FriendlyByteBuf payload) {
        this.payload = payload;
    }

    public int getLoginIndex() {
        return loginIndex;
    }

    public void setLoginIndex(int loginIndex) {
        this.loginIndex = loginIndex;
    }
    
    /**
     * Server-side factory method called by Forge to create login queries.
     * This is called once per connecting client.
     * 
     * The actual challenge packet is created in encode() to ensure fresh
     * state generation at serialization time.
     */
    public static List<Pair<String, S2CLoginQuery>> buildServerQuery(boolean isLocal) {
        LOGGER.debug("buildServerQuery called with isLocal={}, isIntegratedServer={}", 
            isLocal, AuthLogic.isIntegratedServer());
        
        if (isLocal || AuthLogic.isIntegratedServer()) {
            // Skip authentication for local/singleplayer/integrated server
            LOGGER.info("Skipping authentication query for local/integrated server (isLocal={}, isIntegrated={})",
                isLocal, AuthLogic.isIntegratedServer());
            return java.util.Collections.emptyList();
        }
        
        LOGGER.debug("Building authentication query for remote client");
        // Return empty query - payload will be generated in encode()
        return java.util.Collections.singletonList(Pair.of("authlogic:login", new S2CLoginQuery()));
    }

    public static void encode(S2CLoginQuery msg, FriendlyByteBuf buf) {
        // Generate fresh server challenge at encode time
        FriendlyByteBuf query = ServerNetworking.getServerQuery();
        
        // Write payload bytes in a framed way
        buf.writeVarInt(query.readableBytes());
        buf.writeBytes(query, query.readerIndex(), query.readableBytes());
    }

    public static S2CLoginQuery decode(FriendlyByteBuf buf) {
        int len = buf.readVarInt();
        FriendlyByteBuf payload = new FriendlyByteBuf(buf.readBytes(len));
        return new S2CLoginQuery(payload);
    }

    public static void handle(HandshakeHandler h, S2CLoginQuery msg, Supplier<NetworkEvent.Context> ctx) {
        try {
            String serverAddress = getServerAddress(ctx.get());
            
            // Skip authentication for local/integrated server connections
            if (isLocalAddress(serverAddress)) {
                LOGGER.debug("Skipping authentication for local connection: {}", serverAddress);
                // Send an empty/acknowledgement response
                ForgeNetworking.CHANNEL.reply(new C2SQueryResponse(null), ctx.get());
                ctx.get().setPacketHandled(true);
                return;
            }
            
            FriendlyByteBuf response = AuthLogicClient.handleServerChallenge(msg.payload, serverAddress);
            
            ForgeNetworking.CHANNEL.reply(new C2SQueryResponse(response), ctx.get());
            ctx.get().setPacketHandled(true);
            
        } catch (VerificationException e) {
            LOGGER.error("Authentication failed: {}", e.getMessage());
            disconnectWithError(ctx.get(), e.getVisualError());
            ctx.get().setPacketHandled(false);
        } catch (Exception e) {
            LOGGER.error("Unexpected error during authentication", e);
            disconnectWithError(ctx.get(), Component.literal("Authentification errored with the following message: " + e));
            ctx.get().setPacketHandled(false);
        }
    }
    
    /**
     * Checks if the address is a local/integrated server address.
     * Local addresses use memory pipes and have formats like "local:E:xxxxx".
     * 
     * NOTE: We only skip for memory pipe addresses (local:), NOT for localhost/127.0.0.1
     * because a dedicated server running on localhost still requires authentication.
     * 
     * @param address Server address
     * @return true if this is a local memory pipe connection (integrated server)
     */
    private static boolean isLocalAddress(String address) {
        // Only skip for Forge memory pipe addresses used by integrated servers
        return address != null && address.startsWith("local:");
    }
    
    /**
     * Disconnects the client with an error message.
     * 
     * @param ctx Network event context
     * @param message Error message to display
     */
    private static void disconnectWithError(NetworkEvent.Context ctx, Component message) {
        try {
            ctx.getNetworkManager().disconnect(message);
        } catch (Exception e) {
            LOGGER.error("Failed to disconnect client", e);
        }
    }
    
    /**
     * Extracts server address from the network context.
     * 
     * @param ctx Network event context
     * @return Server address (IP:port or hostname)
     */
    private static String getServerAddress(NetworkEvent.Context ctx) {
        try {
            var connection = ctx.getNetworkManager();
            var address = connection.getRemoteAddress();
            return address.toString().replaceFirst("^/", ""); // Remove leading slash
        } catch (Exception e) {
            LOGGER.warn("Could not determine server address, using default", e);
            return "unknown";
        }
    }

    @Override
    public int getAsInt() {
        return this.loginIndex;
    }
}
