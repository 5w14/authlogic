package net.fivew14.authlogic.mixin;

import net.fivew14.authlogic.client.AuthLogicClient;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.multiplayer.JoinMultiplayerScreen;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(JoinMultiplayerScreen.class)
public class MultiplayerScreenMixin {
    @Inject(at = @At("RETURN"), method = "init", cancellable = true)
    public void authlogic$showMultiplayerPasswordSetup(CallbackInfo ci) {
        // Reload trusted servers from disk in case config was edited externally
        AuthLogicClient.getStorage().reloadServers();

        if (AuthLogicClient.openSetupMultiplayerScreen((Screen) (Object) this))
            ci.cancel();
    }
}
