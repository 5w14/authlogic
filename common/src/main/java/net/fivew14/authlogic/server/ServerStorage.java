package net.fivew14.authlogic.server;

import com.mojang.logging.LogUtils;
import net.fivew14.authlogic.crypto.KeysProvider;
import net.fivew14.authlogic.protocol.SerializationUtil;
import net.fivew14.authlogic.utilities.SavedStorage;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

/**
 * Server-side storage for player public keys and server keypair.
 * 
 * Storage format:
 * - server_storage.json: Contains:
 *   - players: Map of UUID -> Base64 public key (for offline mode TOFU)
 *   - offlineUsernames: Map of lowercase username -> UUID (for offline mode username claims)
 *   - onlinePlayers: Set of usernames that authenticated via online mode
 * - server_private_key.txt: Base64 encoded RSA private key + public key
 * 
 * Security model:
 * - Online mode players are tracked by username (Mojang-verified, unique)
 * - Offline mode players are tracked by UUID with TOFU key verification
 * - Once a username authenticates via online mode, it cannot be claimed by offline mode
 * - If online-mode authenticates a username previously claimed by offline-mode,
 *   the offline claim is revoked (Mojang is the source of truth)
 */
public class ServerStorage {
    private static final Logger LOGGER = LogUtils.getLogger();
    
    private Map<UUID, String> playerPublicKeys = new HashMap<>();
    private Map<String, UUID> offlineUsernameToUUID = new HashMap<>();
    private Set<String> onlineModeUsernames = new HashSet<>();
    private KeyPair serverKeyPair;
    
    /**
     * Loads server storage from disk.
     * Creates new files if they don't exist.
     * 
     * @throws IOException if loading fails
     */
    public void load() throws IOException {
        // Load player keys and online mode usernames
        if (Files.exists(SavedStorage.getServerStoragePath())) {
            StorageData data = SavedStorage.readJson(
                SavedStorage.getServerStoragePath(), 
                StorageData.class
            );
            playerPublicKeys = data.players != null ? data.players : new HashMap<>();
            offlineUsernameToUUID = data.offlineUsernames != null ? data.offlineUsernames : new HashMap<>();
            onlineModeUsernames = data.onlinePlayers != null ? data.onlinePlayers : new HashSet<>();
            LOGGER.debug("Loaded {} player keys, {} offline usernames, and {} online-mode usernames", 
                playerPublicKeys.size(), offlineUsernameToUUID.size(), onlineModeUsernames.size());
        } else {
            LOGGER.debug("No existing player keys found, starting fresh");
        }
        
        // Load or generate server keypair
        serverKeyPair = getOrCreateServerKeyPair();
    }
    
    /**
     * Saves server storage to disk.
     * 
     * @throws IOException if saving fails
     */
    public void save() throws IOException {
        StorageData data = new StorageData();
        data.players = playerPublicKeys;
        data.offlineUsernames = offlineUsernameToUUID;
        data.onlinePlayers = onlineModeUsernames;
        SavedStorage.writeJson(SavedStorage.getServerStoragePath(), data);
        LOGGER.debug("Saved server storage with {} player keys, {} offline usernames, and {} online-mode usernames", 
            playerPublicKeys.size(), offlineUsernameToUUID.size(), onlineModeUsernames.size());
    }
    
    /**
     * Stores a player's public key.
     * 
     * @param uuid Player UUID
     * @param publicKey Player's RSA public key
     */
    public void storePlayerKey(UUID uuid, PublicKey publicKey) {
        byte[] keyBytes = SerializationUtil.serializePublicKey(publicKey);
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        playerPublicKeys.put(uuid, base64Key);
    }
    
    /**
     * Gets a player's public key.
     * 
     * @param uuid Player UUID
     * @return Optional containing public key if registered
     */
    public Optional<PublicKey> getPlayerKey(UUID uuid) {
        String base64Key = playerPublicKeys.get(uuid);
        if (base64Key == null) {
            return Optional.empty();
        }
        
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PublicKey publicKey = SerializationUtil.deserializePublicKey(keyBytes, "RSA");
            return Optional.of(publicKey);
        } catch (Exception e) {
            LOGGER.error("Failed to deserialize public key for {}", uuid, e);
            return Optional.empty();
        }
    }
    
    /**
     * Checks if a player is registered.
     * 
     * @param uuid Player UUID
     * @return true if player has a stored public key
     */
    public boolean isPlayerRegistered(UUID uuid) {
        return playerPublicKeys.containsKey(uuid);
    }
    
    /**
     * Removes a player's stored public key.
     * This is used when an admin needs to reset a player's TOFU state,
     * for example when a player changes their password.
     * 
     * @param uuid Player UUID
     * @return true if a key was removed, false if no key existed
     */
    public boolean removePlayerKey(UUID uuid) {
        return playerPublicKeys.remove(uuid) != null;
    }
    
    /**
     * Gets all registered player UUIDs.
     * 
     * @return Set of all player UUIDs with stored keys
     */
    public Set<UUID> getRegisteredPlayers() {
        return Collections.unmodifiableSet(playerPublicKeys.keySet());
    }
    
    /**
     * Records a username as having authenticated via online mode.
     * This prevents offline-mode impersonation of this username.
     * 
     * @param username The Mojang-verified username (case-sensitive)
     */
    public void recordOnlineModeUsername(String username) {
        onlineModeUsernames.add(username.toLowerCase());
        LOGGER.debug("Recorded online-mode username: {}", username);
    }
    
    /**
     * Checks if a username has ever authenticated via online mode.
     * If true, this username can ONLY authenticate via online mode.
     * 
     * @param username Username to check (case-insensitive)
     * @return true if this username is known to be an online-mode player
     */
    public boolean isOnlineModeUsername(String username) {
        return onlineModeUsernames.contains(username.toLowerCase());
    }
    
    /**
     * Removes a username from the online-mode registry.
     * This should only be used by admins to reset a player's auth mode.
     * 
     * @param username Username to remove
     * @return true if the username was removed, false if it wasn't registered
     */
    public boolean removeOnlineModeUsername(String username) {
        return onlineModeUsernames.remove(username.toLowerCase());
    }
    
    /**
     * Gets all online-mode usernames.
     * 
     * @return Set of all usernames that authenticated via online mode
     */
    public Set<String> getOnlineModeUsernames() {
        return Collections.unmodifiableSet(onlineModeUsernames);
    }
    
    /**
     * Records an offline-mode username claim.
     * Maps the username to the UUID that claimed it.
     * 
     * @param username The username being claimed (case-insensitive)
     * @param uuid The UUID of the offline player claiming this username
     */
    public void recordOfflineUsername(String username, UUID uuid) {
        offlineUsernameToUUID.put(username.toLowerCase(), uuid);
        LOGGER.debug("Recorded offline username claim: {} -> {}", username, uuid);
    }
    
    /**
     * Gets the UUID that claimed a username via offline mode.
     * 
     * @param username Username to look up (case-insensitive)
     * @return Optional containing the UUID if claimed, empty otherwise
     */
    public Optional<UUID> getOfflineUsernameOwner(String username) {
        return Optional.ofNullable(offlineUsernameToUUID.get(username.toLowerCase()));
    }
    
    /**
     * Checks if a username is claimed by an offline-mode player.
     * 
     * @param username Username to check (case-insensitive)
     * @return true if this username is claimed by an offline player
     */
    public boolean isOfflineUsername(String username) {
        return offlineUsernameToUUID.containsKey(username.toLowerCase());
    }
    
    /**
     * Revokes an offline-mode username claim and removes the associated TOFU key.
     * This is called when an online-mode player authenticates with a username
     * that was previously claimed by an offline player.
     * 
     * @param username Username to revoke (case-insensitive)
     * @return true if a claim was revoked, false if no claim existed
     */
    public boolean revokeOfflineUsernameClaim(String username) {
        UUID claimingUUID = offlineUsernameToUUID.remove(username.toLowerCase());
        if (claimingUUID != null) {
            // Also remove the TOFU key for this UUID
            playerPublicKeys.remove(claimingUUID);
            LOGGER.warn("Revoked offline claim for username '{}' (was UUID: {}). " +
                "Online-mode player has taken ownership.", username, claimingUUID);
            return true;
        }
        return false;
    }
    
    /**
     * Gets or creates the server's RSA keypair.
     * Loads from disk if exists, otherwise generates and saves new keypair.
     * 
     * @return Server's RSA keypair
     */
    public KeyPair getOrCreateServerKeyPair() {
        if (serverKeyPair != null) {
            return serverKeyPair;
        }
        
        try {
            if (Files.exists(SavedStorage.getServerPrivateKeyPath())) {
                // Load existing keypair
                String data = SavedStorage.readText(SavedStorage.getServerPrivateKeyPath());
                String[] parts = data.split("\n");
                if (parts.length != 2) {
                    throw new IOException("Invalid server key file format");
                }
                
                byte[] privateKeyBytes = Base64.getDecoder().decode(parts[0]);
                byte[] publicKeyBytes = Base64.getDecoder().decode(parts[1]);
                
                PrivateKey privateKey = SerializationUtil.deserializePrivateKey(privateKeyBytes, "RSA");
                PublicKey publicKey = SerializationUtil.deserializePublicKey(publicKeyBytes, "RSA");
                
                serverKeyPair = new KeyPair(publicKey, privateKey);
                LOGGER.info("Loaded server RSA keypair from disk");
                
            } else {
                // Generate new keypair
                serverKeyPair = KeysProvider.generateConstantKeyPair();
                
                // Save to disk
                byte[] privateKeyBytes = SerializationUtil.serializePrivateKey(serverKeyPair.getPrivate());
                byte[] publicKeyBytes = SerializationUtil.serializePublicKey(serverKeyPair.getPublic());
                
                String data = Base64.getEncoder().encodeToString(privateKeyBytes) + "\n" +
                             Base64.getEncoder().encodeToString(publicKeyBytes);
                
                SavedStorage.writeText(SavedStorage.getServerPrivateKeyPath(), data);
                LOGGER.info("Generated and saved new server RSA keypair");
            }
            
            return serverKeyPair;
            
        } catch (IOException e) {
            throw new RuntimeException("Failed to load/create server keypair", e);
        }
    }
    
    /**
     * Gets the server's public key.
     * 
     * @return Server's RSA public key
     */
    public PublicKey getServerPublicKey() {
        if (serverKeyPair == null) {
            getOrCreateServerKeyPair();
        }
        return serverKeyPair.getPublic();
    }
    
    /**
     * Gets the server's private key.
     * 
     * @return Server's RSA private key
     */
    public PrivateKey getServerPrivateKey() {
        if (serverKeyPair == null) {
            getOrCreateServerKeyPair();
        }
        return serverKeyPair.getPrivate();
    }
    
    /**
     * Internal class for JSON serialization.
     */
    private static class StorageData {
        public Map<UUID, String> players = new HashMap<>();
        public Map<String, UUID> offlineUsernames = new HashMap<>();
        public Set<String> onlinePlayers = new HashSet<>();
    }
}
