package net.fivew14.authlogic.forge.networking;

import net.fivew14.authlogic.AuthLogic;
import net.fivew14.authlogic.forge.AuthLogicForge;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.simple.SimpleChannel;

public class ForgeNetworking {
    private static final String PROTOCOL = "1";

    private static final SimpleChannel CHANNEL = NetworkRegistry.newSimpleChannel(
            AuthLogic.NETWORKING_CHANNEL_ID, () -> PROTOCOL, PROTOCOL::equals, PROTOCOL::equals
    );

    public static void bootstrap() {
        int id = 0;

        S2CLoginQuery.register(CHANNEL, id++);
        C2SQueryResponse.register(CHANNEL, id++);
    }
}
