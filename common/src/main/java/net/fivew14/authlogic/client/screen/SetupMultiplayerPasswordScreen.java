package net.fivew14.authlogic.client.screen;

import net.fivew14.authlogic.client.AuthLogicClient;
import net.fivew14.authlogic.client.ClientAuthHandler;
import net.fivew14.authlogic.client.ClientStorage;
import net.minecraft.ChatFormatting;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.gui.screens.TitleScreen;
import net.minecraft.network.chat.Component;

public class SetupMultiplayerPasswordScreen extends Screen {
    private final Screen returnTo;

    EditBox editBox;

    public SetupMultiplayerPasswordScreen(Screen returnTo) {
        super(Component.translatable("authlogic.screen.setup_password.title"));
        this.returnTo = returnTo;
    }

    Component saveError = Component.empty();

    @Override
    protected void init() {
        int width = 200;

        editBox = addRenderableWidget(new EditBox(this.minecraft.font, this.width / 2 - width / 2,
                this.height / 2, width, 20, Component.translatable("authlogic.screen.setup_password.title")));

        addRenderableWidget(new Button.Builder(Component.translatable("authlogic.screen.setup_password.button.save"), this::storePassword)
                .bounds(this.width / 2 - width / 2, this.height - 60, width, 20).build());

        addRenderableWidget(new Button.Builder(Component.translatable("authlogic.screen.setup_password.button.cancel"), (b) -> this.onClose())
                .bounds(this.width / 2 - width / 2, this.height - 35, width, 20).build());


    }

    private void storePassword(Button button) {
        String password = editBox.getValue();

        if (password.length() < 4) {
            saveError = Component.translatable("authlogic.screen.setup_password.error.too_short")
                    .withStyle(ChatFormatting.RED);
            return;
        }

        // Hash and save password immediately
        String passwordHash = ClientStorage.hashPassword(password);
        try {
            AuthLogicClient.getStorage().savePasswordHashToDisk(passwordHash);
            AuthLogicClient.getStorage().save();
        } catch (Exception e) {
            saveError = Component.translatable("authlogic.screen.setup_password.error.save_failed", e.getMessage())
                    .withStyle(ChatFormatting.RED);
            return;
        }

        // Set provider for current session (uses saved hash)
        ClientAuthHandler.setPasswordProvider(new ClientAuthHandler
                .SupplierPasswordProvider(() -> password, false));

        this.minecraft.setScreen(this.returnTo);
    }

    @Override
    public void render(GuiGraphics guiGraphics, int i, int j, float f) {
        renderBackground(guiGraphics);

        guiGraphics.drawCenteredString(this.minecraft.font,
                Component.translatable("authlogic.screen.setup_password.title").withStyle(ChatFormatting.BOLD),
                this.width / 2, this.height / 2 - 45, 0xFFFFFFFF);

        guiGraphics.drawCenteredString(this.minecraft.font,
                Component.translatable("authlogic.screen.setup_password.description"),
                this.width / 2, this.height / 2 - 25, 0xFFFFFFFF);

        guiGraphics.drawCenteredString(this.minecraft.font,
                Component.translatable("authlogic.screen.setup_password.warning").withStyle(ChatFormatting.ITALIC, ChatFormatting.RED),
                this.width / 2, this.height / 2 + 35, 0xFFFFFFFF);

        guiGraphics.drawCenteredString(this.minecraft.font, saveError,
                this.width / 2, this.height - 75, 0xFFFFFFFF);

        super.render(guiGraphics, i, j, f);
    }

    @Override
    public void onClose() {
        minecraft.setScreen(new TitleScreen());
    }
}