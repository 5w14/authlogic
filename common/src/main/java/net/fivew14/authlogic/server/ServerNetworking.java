package net.fivew14.authlogic.server;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;

public class ServerNetworking {
    public static FriendlyByteBuf getServerQuery() {
        // TO SEND:
        // - temp key
        // - const key
        // - nonce
        // - signature (tempkey + nonce)

        return new FriendlyByteBuf(Unpooled.buffer());
    }

    public static void validateClientResponse(FriendlyByteBuf buf, UsernameGetter usernameGetter) {
    }

    @FunctionalInterface
    public interface UsernameGetter {
        String getUsername();
    }
}
