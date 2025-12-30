package net.fivew14.authlogic.client;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;

public class ClientNetworking {
    // handle & validate server query
    public static FriendlyByteBuf handleLoginQuery(FriendlyByteBuf buf) {
        // TO VALIDATE:
        // - nonce

        // TO SEND:
        // - temp client key
        // - client nonce
        // - ECDH encrypted blob of
        //   - client public key
        //   - signature ( client nonce, server nonce, client temp key, server temp key )

        return new FriendlyByteBuf(Unpooled.buffer());
    }
}
