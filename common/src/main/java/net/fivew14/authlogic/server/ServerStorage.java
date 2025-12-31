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
 * - server_storage.json: Map of UUID -> Base64 public key
 * - server_private_key.txt: Base64 encoded RSA private key + public key
 */
public class ServerStorage {
    private static final Logger LOGGER = LogUtils.getLogger();
    
    private Map<UUID, String> playerPublicKeys = new HashMap<>();
    private KeyPair serverKeyPair;
    
    /**
     * Loads server storage from disk.
     * Creates new files if they don't exist.
     * 
     * @throws IOException if loading fails
     */
    public void load() throws IOException {
        // Load player keys
        if (Files.exists(SavedStorage.getServerStoragePath())) {
            StorageData data = SavedStorage.readJson(
                SavedStorage.getServerStoragePath(), 
                StorageData.class
            );
            playerPublicKeys = data.players != null ? data.players : new HashMap<>();
            LOGGER.info("Loaded {} player keys", playerPublicKeys.size());
        } else {
            LOGGER.info("No existing player keys found, starting fresh");
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
        SavedStorage.writeJson(SavedStorage.getServerStoragePath(), data);
        LOGGER.debug("Saved server storage with {} player keys", playerPublicKeys.size());
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
    }
}
