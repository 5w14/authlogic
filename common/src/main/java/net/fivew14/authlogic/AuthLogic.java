package net.fivew14.authlogic;

import dev.architectury.platform.Platform;
import dev.architectury.utils.Env;
import net.fivew14.authlogic.crypto.KeysProvider;
import net.fivew14.authlogic.server.AuthLogicDedicated;
import net.minecraft.resources.ResourceLocation;

public final class AuthLogic {
    public static final String MOD_ID = "authlogic";
    public static final ResourceLocation NETWORKING_CHANNEL_ID = AuthLogic.id("login");

    public static void init() {
        KeysProvider.bootstrap();

        if (Platform.getEnvironment() == Env.SERVER)
            AuthLogicDedicated.onDedicatedStartup();
    }

    public static boolean isOnDedicated() {
        return AuthLogicDedicated.isRunningDedicated();
    }

    public static ResourceLocation id(String location) {
        return new ResourceLocation(MOD_ID, location);
    }
}
