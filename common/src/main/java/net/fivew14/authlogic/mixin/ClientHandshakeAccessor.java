package net.fivew14.authlogic.mixin;

import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.Connection;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(ClientHandshakePacketListenerImpl.class)
public interface ClientHandshakeAccessor {
    @Accessor("serverData") ServerData authlogic$getServerData();
    @Accessor("connection") Connection authlogic$getConnection();
}
