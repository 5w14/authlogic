package net.fivew14.authlogic.fabric;

import net.fivew14.authlogic.AuthLogic;
import net.fabricmc.api.ModInitializer;
import net.fivew14.authlogic.fabric.networking.FabricServerNetworking;

public final class AuthLogicFabric implements ModInitializer {
    @Override
    public void onInitialize() {
        AuthLogic.init();
        FabricServerNetworking.bootstrap();
    }
}
