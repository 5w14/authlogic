package net.fivew14.authlogic.forge;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import net.fivew14.authlogic.AuthLogic;
import dev.architectury.platform.forge.EventBuses;
import net.fivew14.authlogic.client.AuthLogicClient;
import net.fivew14.authlogic.forge.networking.ForgeNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;
import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.event.lifecycle.FMLClientSetupEvent;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.simple.SimpleChannel;

@Mod(AuthLogic.MOD_ID)
public final class AuthLogicForge {
    public AuthLogicForge() {
        EventBuses.registerModEventBus(AuthLogic.MOD_ID, FMLJavaModLoadingContext.get().getModEventBus());
        AuthLogic.init();

        var bus = FMLJavaModLoadingContext.get().getModEventBus();
        bus.addListener(this::clientInit);

        ForgeNetworking.bootstrap();
    }

    public void clientInit(FMLClientSetupEvent event) {
        AuthLogicClient.onClientInit();
    }
}
