package net.fivew14.authlogic.mixin;

import com.mojang.authlib.GameProfile;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/**
 * Mixin accessor to get the protected gameProfile field from ServerLoginPacketListenerImpl.
 */
@Mixin(ServerLoginPacketListenerImpl.class)
public interface ServerLoginPacketListenerImplAccessor {
    
    @Accessor("gameProfile")
    GameProfile authlogic$getGameProfile();
}
