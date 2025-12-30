package net.fivew14.authlogic.fabric.client;

import net.fabricmc.api.ClientModInitializer;
import net.fivew14.authlogic.client.AuthLogicClient;
import net.fivew14.authlogic.fabric.networking.FabricClientNetworking;

public final class AuthLogicFabricClient implements ClientModInitializer {
    @Override
    public void onInitializeClient() {
        AuthLogicClient.onClientInit();
        FabricClientNetworking.bootstrap();
    }
}
