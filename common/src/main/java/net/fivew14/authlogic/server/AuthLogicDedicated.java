package net.fivew14.authlogic.server;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.suggestion.Suggestions;
import com.mojang.brigadier.suggestion.SuggestionsBuilder;
import com.mojang.logging.LogUtils;
import dev.architectury.event.events.common.CommandRegistrationEvent;
import dev.architectury.event.events.common.LifecycleEvent;
import dev.architectury.event.events.common.PlayerEvent;
import dev.architectury.event.events.common.TickEvent;
import net.fivew14.authlogic.AuthLogic;
import net.minecraft.commands.CommandBuildContext;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class AuthLogicDedicated {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static boolean isRunningDedicated;
    private static boolean isActive = false;
    private static MinecraftServer server = null;
    
    /**
     * Counter for cleanup tick interval.
     * Cleanup runs every CLEANUP_INTERVAL_TICKS ticks (roughly every 5 seconds at 20 TPS).
     */
    private static int tickCounter = 0;
    private static final int CLEANUP_INTERVAL_TICKS = 100; // 5 seconds at 20 TPS

    public static void onDedicatedStartup() {
        isRunningDedicated = true;
        LifecycleEvent.SERVER_STARTED.register(AuthLogicDedicated::serverStarting);
        PlayerEvent.PLAYER_JOIN.register(AuthLogicDedicated::onPlayerJoin);
        TickEvent.SERVER_POST.register(AuthLogicDedicated::onServerTick);

        CommandRegistrationEvent.EVENT.register(AuthLogicDedicated::registerCommands);
    }

    private static void serverStarting(MinecraftServer server) {
        AuthLogicDedicated.server = server;

        if (server.usesAuthentication()) {
            LOGGER.error("This server is running in secure connection mode which disables the functionality of AuthLogic.");
            LOGGER.error("Please update your server.properties value of online-mode to false.");
        }

        isActive = !server.usesAuthentication();
    }

    private static void registerCommands(CommandDispatcher<CommandSourceStack> dispatcher, CommandBuildContext buildContext, Commands.CommandSelection selection) {
        dispatcher.register(
            Commands.literal("authlogic")
                .requires(source -> source.hasPermission(3)) // Require OP level 3
                .then(Commands.literal("reset")
                    .then(Commands.argument("player", StringArgumentType.word())
                            .suggests(AuthLogicDedicated::getSuggestions)
                        .executes(AuthLogicDedicated::executeResetKey)))
                .then(Commands.literal("list")
                    .executes(AuthLogicDedicated::executeListPlayers))
                .then(Commands.literal("status")
                    .executes(AuthLogicDedicated::executeStatus))
                .then(Commands.literal("whitelist")
                    .then(Commands.literal("on")
                        .executes(AuthLogicDedicated::executeWhitelistOn))
                    .then(Commands.literal("off")
                        .executes(AuthLogicDedicated::executeWhitelistOff))
                    .then(Commands.literal("list")
                        .executes(AuthLogicDedicated::executeWhitelistList))
                    .then(Commands.literal("add")
                        .then(Commands.argument("username", StringArgumentType.word())
                            .executes(AuthLogicDedicated::executeWhitelistAdd)))
                    .then(Commands.literal("remove")
                        .then(Commands.argument("username", StringArgumentType.word())
                            .suggests(AuthLogicDedicated::getWhitelistSuggestions)
                            .executes(AuthLogicDedicated::executeWhitelistRemove))))
        );

    }
    
    /**
     * Resets a player's stored public key by username.
     * This allows the player to re-authenticate with a new key (e.g., after password change).
     */
    private static int executeResetKey(CommandContext<CommandSourceStack> context) {
        String playerName = StringArgumentType.getString(context, "player");
        CommandSourceStack source = context.getSource();
        
        // Find UUID for the player name by looking through registered players
        ServerStorage storage = AuthLogic.getServerStorage();
        Set<UUID> registeredPlayers = storage.getRegisteredPlayers();
        
        // Try to find the player by checking the server's player list or stored data
        // Since we store by UUID, we need to find the UUID for this username
        UUID targetUuid = null;
        
        // First check if player is online
        if (server != null) {
            ServerPlayer onlinePlayer = server.getPlayerList().getPlayerByName(playerName);
            if (onlinePlayer != null) {
                targetUuid = onlinePlayer.getUUID();
            }
        }
        
        // If not online, try offline UUID (for offline mode servers)
        if (targetUuid == null) {
            // In offline mode, UUID is derived from username
            targetUuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + playerName).getBytes());
        }
        
        if (!storage.isPlayerRegistered(targetUuid)) {
            source.sendFailure(Component.literal("Player '" + playerName + "' has no stored key."));
            return 0;
        }
        
        boolean removed = storage.removePlayerKey(targetUuid);
        if (removed) {
            try {
                storage.save();
                source.sendSuccess(() -> Component.literal(
                    "Successfully reset key for player '" + playerName + "'. They will need to re-authenticate."
                ), true);
                LOGGER.debug("Admin {} reset authentication key for player {}", 
                    source.getTextName(), playerName);
                return 1;
            } catch (IOException e) {
                LOGGER.error("Failed to save storage after key reset", e);
                source.sendFailure(Component.literal("Key removed but failed to save: " + e.getMessage()));
                return 0;
            }
        } else {
            source.sendFailure(Component.literal("Failed to remove key for player '" + playerName + "'."));
            return 0;
        }
    }
    
    /**
     * Lists all players with stored authentication keys.
     */
    private static int executeListPlayers(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        Set<UUID> registeredPlayers = storage.getRegisteredPlayers();
        
        if (registeredPlayers.isEmpty()) {
            source.sendSuccess(() -> Component.literal("No players have registered authentication keys."), false);
            return 1;
        }
        
        source.sendSuccess(() -> Component.literal("Registered players (" + registeredPlayers.size() + "):"), false);
        for (UUID uuid : registeredPlayers) {
            // Try to get player name if online
            String playerName = null;
            if (server != null) {
                ServerPlayer player = server.getPlayerList().getPlayer(uuid);
                if (player != null) {
                    playerName = player.getName().getString();
                }
            }
            
            final String displayName = playerName != null 
                ? playerName + " (" + uuid + ")"
                : uuid.toString();
            source.sendSuccess(() -> Component.literal("  - " + displayName), false);
        }
        
        return 1;
    }
    
    /**
     * Shows AuthLogic status information.
     */
    private static int executeStatus(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        
        source.sendSuccess(() -> Component.literal("=== AuthLogic Status ==="), false);
        source.sendSuccess(() -> Component.literal("Active: " + (isActive ? "Yes" : "No (online-mode enabled)")), false);
        source.sendSuccess(() -> Component.literal("Registered players: " + storage.getRegisteredPlayers().size()), false);
        source.sendSuccess(() -> Component.literal("Pending auth states: " + ServerAuthState.getAuthStateCount()), false);
        source.sendSuccess(() -> Component.literal("Pending joins: " + ServerAuthState.getAuthenticatedPlayersCount()), false);
        source.sendSuccess(() -> Component.literal("Whitelist: " + (storage.isWhitelistEnabled() ? "Enabled" : "Disabled")), false);
        
        return 1;
    }
    
    // ==================== Whitelist Commands ====================
    
    /**
     * Enables the AuthLogic whitelist.
     */
    private static int executeWhitelistOn(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        
        try {
            storage.setWhitelistEnabled(true);
            source.sendSuccess(() -> Component.literal("AuthLogic whitelist enabled."), true);
            LOGGER.debug("Admin {} enabled AuthLogic whitelist", source.getTextName());
            return 1;
        } catch (IOException e) {
            LOGGER.error("Failed to enable whitelist", e);
            source.sendFailure(Component.literal("Failed to save whitelist: " + e.getMessage()));
            return 0;
        }
    }
    
    /**
     * Disables the AuthLogic whitelist.
     */
    private static int executeWhitelistOff(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        
        try {
            storage.setWhitelistEnabled(false);
            source.sendSuccess(() -> Component.literal("AuthLogic whitelist disabled."), true);
            LOGGER.debug("Admin {} disabled AuthLogic whitelist", source.getTextName());
            return 1;
        } catch (IOException e) {
            LOGGER.error("Failed to disable whitelist", e);
            source.sendFailure(Component.literal("Failed to save whitelist: " + e.getMessage()));
            return 0;
        }
    }
    
    /**
     * Lists all whitelisted usernames.
     */
    private static int executeWhitelistList(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        
        boolean enabled = storage.isWhitelistEnabled();
        Set<String> usernames = storage.getWhitelistedUsernames();
        
        source.sendSuccess(() -> Component.literal("AuthLogic whitelist is " + (enabled ? "enabled" : "disabled") + "."), false);
        
        if (usernames.isEmpty()) {
            source.sendSuccess(() -> Component.literal("No players are whitelisted."), false);
        } else {
            source.sendSuccess(() -> Component.literal("Whitelisted players (" + usernames.size() + "):"), false);
            for (String username : usernames) {
                source.sendSuccess(() -> Component.literal("  - " + username), false);
            }
        }
        
        return 1;
    }
    
    /**
     * Adds a username to the whitelist.
     */
    private static int executeWhitelistAdd(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        String username = StringArgumentType.getString(context, "username");
        
        try {
            boolean added = storage.addToWhitelist(username);
            if (added) {
                source.sendSuccess(() -> Component.literal("Added '" + username + "' to the AuthLogic whitelist."), true);
                LOGGER.debug("Admin {} added '{}' to AuthLogic whitelist", source.getTextName(), username);
            } else {
                source.sendSuccess(() -> Component.literal("'" + username + "' is already whitelisted."), false);
            }
            return 1;
        } catch (IOException e) {
            LOGGER.error("Failed to add to whitelist", e);
            source.sendFailure(Component.literal("Failed to save whitelist: " + e.getMessage()));
            return 0;
        }
    }
    
    /**
     * Removes a username from the whitelist.
     */
    private static int executeWhitelistRemove(CommandContext<CommandSourceStack> context) {
        CommandSourceStack source = context.getSource();
        ServerStorage storage = AuthLogic.getServerStorage();
        String username = StringArgumentType.getString(context, "username");
        
        try {
            boolean removed = storage.removeFromWhitelist(username);
            if (removed) {
                source.sendSuccess(() -> Component.literal("Removed '" + username + "' from the AuthLogic whitelist."), true);
                LOGGER.debug("Admin {} removed '{}' from AuthLogic whitelist", source.getTextName(), username);
            } else {
                source.sendSuccess(() -> Component.literal("'" + username + "' was not whitelisted."), false);
            }
            return 1;
        } catch (IOException e) {
            LOGGER.error("Failed to remove from whitelist", e);
            source.sendFailure(Component.literal("Failed to save whitelist: " + e.getMessage()));
            return 0;
        }
    }
    
    /**
     * Provides tab completion for whitelist remove command.
     */
    private static CompletableFuture<Suggestions> getWhitelistSuggestions(CommandContext<CommandSourceStack> ctx, SuggestionsBuilder sugg) {
        ServerStorage storage = AuthLogic.getServerStorage();
        for (String username : storage.getWhitelistedUsernames()) {
            sugg.suggest(username);
        }
        return sugg.buildFuture();
    }

    /**
     * Called when a player joins the server.
     * Verifies that the player completed authentication during login.
     * If not authenticated, disconnects the player.
     * 
     * @param player The joining player
     */
    private static void onPlayerJoin(ServerPlayer player) {
        // Skip if not active (online-mode server) or singleplayer
        if (!isActive || server == null || server.isSingleplayer()) {
            LOGGER.debug("Skipping auth check for player join (isActive={}, server={}, singleplayer={})",
                isActive, server != null, server != null && server.isSingleplayer());
            return;
        }
        
        // Check if player was authenticated during login (by username)
        String username = player.getName().getString();
        LOGGER.debug("Player '{}' joining, checking authentication status", username);
        boolean wasAuthenticated = ServerAuthState.consumeAuthentication(username);
        
        if (!wasAuthenticated) {
            LOGGER.warn("Player {} ({}) joined without completing AuthLogic authentication - disconnecting",
                username, player.getUUID());
            player.connection.disconnect(Component.literal(
                "Authentication required. Please install the AuthLogic mod to play on this server."
            ));
        } else {
            LOGGER.debug("Player {} ({}) authentication verified on join",
                username, player.getUUID());
        }
    }
    
    /**
     * Called every server tick.
     * Periodically cleans up stale authentication states.
     * 
     * @param server The Minecraft server
     */
    private static void onServerTick(MinecraftServer server) {
        if (!isActive) {
            return;
        }
        
        tickCounter++;
        if (tickCounter >= CLEANUP_INTERVAL_TICKS) {
            tickCounter = 0;
            ServerAuthState.cleanupStaleEntries();
        }
    }

    public static boolean isRunningDedicated() {
        return isRunningDedicated;
    }

    public static boolean isActive() {
        return isActive;
    }

    private static CompletableFuture<Suggestions> getSuggestions(CommandContext<CommandSourceStack> ctx, SuggestionsBuilder sugg) {
        ServerStorage storage = AuthLogic.getServerStorage();
        Set<UUID> registeredPlayers = storage.getRegisteredPlayers();

        for (UUID uuid : registeredPlayers) {
            String playerName = null;

            if (server != null) {
                ServerPlayer player = server.getPlayerList().getPlayer(uuid);
                if (player != null) {
                    playerName = player.getName().getString();
                }
            }

            if (playerName != null)
                sugg.suggest(playerName);
        }

        return sugg.buildFuture();
    }
}
