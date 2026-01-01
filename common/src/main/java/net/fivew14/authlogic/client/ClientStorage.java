package net.fivew14.authlogic.client;

import com.mojang.logging.LogUtils;
import net.fivew14.authlogic.crypto.PasswordBasedKeyDerivation;
import net.fivew14.authlogic.protocol.SerializationUtil;
import net.fivew14.authlogic.utilities.SavedStorage;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Client-side storage for derived keypair and trusted servers.
 * 
 * SECURITY: Client keypair is derived from password and NEVER stored on disk.
 * Only password hash and trusted server keys are persisted.
 * 
 * Storage format:
 * - client_password.txt: Password hash (optional, for verification)
 * - client_servers.json: Map of server address -> Base64 public key
 */
public class ClientStorage {
    private static final Logger LOGGER = LogUtils.getLogger();
    
    // Runtime only - derived from password hash
    private KeyPair clientKeyPair = null;
    private String cachedPasswordHash = null; // SHA-256 hash, not plain password
    
    // Persistent - trusted servers
    private Map<String, String> trustedServers = new HashMap<>();
    
    /**
     * Loads client storage from disk.
     * Only loads trusted servers list; keypair must be derived separately.
     * 
     * @throws IOException if loading fails
     */
    public void load() throws IOException {
        loadServers();
    }
    
    /**
     * Loads or reloads the trusted servers list from disk.
     * This allows hot-reloading the config without restarting the client.
     * 
     * @throws IOException if loading fails
     */
    public void loadServers() throws IOException {
        if (Files.exists(SavedStorage.getClientServersPath())) {
            ServersData data = SavedStorage.readJson(
                SavedStorage.getClientServersPath(),
                ServersData.class
            );
            trustedServers = data.servers != null ? data.servers : new HashMap<>();
            LOGGER.debug("Loaded {} trusted servers", trustedServers.size());
        } else {
            LOGGER.debug("No existing trusted servers found");
            trustedServers = new HashMap<>();
        }
    }
    
    /**
     * Reloads the trusted servers list from disk.
     * Convenience method that logs any errors instead of throwing.
     * Safe to call from UI code.
     */
    public void reloadServers() {
        try {
            loadServers();
            LOGGER.debug("Reloaded trusted servers from disk");
        } catch (IOException e) {
            LOGGER.error("Failed to reload trusted servers", e);
        }
    }
    
    /**
     * Saves client storage to disk.
     * Only saves trusted servers list; keypair is never stored.
     * 
     * @throws IOException if saving fails
     */
    public void save() throws IOException {
        ServersData data = new ServersData();
        data.servers = trustedServers;
        SavedStorage.writeJson(SavedStorage.getClientServersPath(), data);
        LOGGER.debug("Saved {} trusted servers", trustedServers.size());
    }
    
    /**
     * Derives client keypair from password hash and server public key.
     * Stores keypair in memory only - NEVER written to disk.
     * 
     * SECURITY: This method expects a SHA-256 hash, NOT a plain password.
     * Call hashPassword() first to convert plain text to hash.
     * 
     * @param passwordHash SHA-256 hash of the password (64 hex characters)
     * @param serverPublicKey Server's RSA public key
     */
    public void deriveClientKeys(String passwordHash, PublicKey serverPublicKey) {
        clientKeyPair = PasswordBasedKeyDerivation.deriveKeyPair(passwordHash, serverPublicKey);
        cachedPasswordHash = passwordHash; // Cache hash (not plain password) for session
        LOGGER.debug("Derived client keypair from password hash");
    }
    
    /**
     * Hashes a plain password using SHA-256.
     * Call this immediately when receiving password from user.
     * 
     * @param plainPassword Plain text password
     * @return SHA-256 hash as hex string (64 characters)
     */
    public static String hashPassword(String plainPassword) {
        return PasswordBasedKeyDerivation.hashPassword(plainPassword);
    }
    
    /**
     * Gets the client's keypair.
     * Must call deriveClientKeys() first.
     * 
     * @return Client's RSA keypair
     * @throws IllegalStateException if keypair not derived yet
     */
    public KeyPair getClientKeyPair() {
        if (clientKeyPair == null) {
            throw new IllegalStateException("Client keypair not derived. Call deriveClientKeys() first.");
        }
        return clientKeyPair;
    }
    
    /**
     * Gets the client's public key.
     * 
     * @return Optional containing public key if derived
     */
    public Optional<PublicKey> getClientPublicKey() {
        if (clientKeyPair == null) {
            return Optional.empty();
        }
        return Optional.of(clientKeyPair.getPublic());
    }
    
    /**
     * Clears cached keypair and password hash from memory.
     * Should be called when client disconnects for security.
     */
    public void clearKeys() {
        clientKeyPair = null;
        cachedPasswordHash = null;
        LOGGER.debug("Cleared client keypair and password hash from memory");
    }
    
    /**
     * Trusts a server by storing its public key.
     * 
     * @param serverAddress Server address (IP:port or hostname)
     * @param serverPublicKey Server's RSA public key
     */
    public void trustServer(String serverAddress, PublicKey serverPublicKey) {
        byte[] keyBytes = SerializationUtil.serializePublicKey(serverPublicKey);
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        trustedServers.put(serverAddress, base64Key);
        LOGGER.debug("Trusted server: {}", serverAddress);
    }
    
    /**
     * Gets a trusted server's public key.
     * 
     * @param serverAddress Server address
     * @return Optional containing public key if trusted
     */
    public Optional<PublicKey> getServerKey(String serverAddress) {
        String base64Key = trustedServers.get(serverAddress);
        if (base64Key == null) {
            return Optional.empty();
        }
        
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PublicKey publicKey = SerializationUtil.deserializePublicKey(keyBytes, "RSA");
            return Optional.of(publicKey);
        } catch (Exception e) {
            LOGGER.error("Failed to deserialize server key for {}", serverAddress, e);
            return Optional.empty();
        }
    }
    
    /**
     * Checks if a server is trusted.
     * 
     * @param serverAddress Server address
     * @return true if server is in trusted list
     */
    public boolean isServerTrusted(String serverAddress) {
        return trustedServers.containsKey(serverAddress);
    }
    
    /**
     * Removes a server from trusted list.
     * 
     * @param serverAddress Server address
     */
    public void untrustServer(String serverAddress) {
        trustedServers.remove(serverAddress);
        LOGGER.debug("Removed trust for server: {}", serverAddress);
    }
    
    /**
     * Saves password hash to disk for verification.
     * This allows saving a SHA-256 hash (not the plain password or full bcrypt hash).
     * Useful for quick password verification without storing sensitive data.
     * 
     * SECURITY: Stores only SHA-256 hash, NOT the plain password.
     * 
     * @param passwordHash SHA-256 hash of the password (64 hex characters)
     * @throws IOException if saving fails
     */
    public void savePasswordHashToDisk(String passwordHash) throws IOException {
        if (passwordHash == null || passwordHash.length() != 64) {
            throw new IllegalArgumentException("Must provide SHA-256 hash (64 hex chars)");
        }
        SavedStorage.writeText(SavedStorage.getClientPasswordPath(), passwordHash);
        LOGGER.debug("Saved password hash to disk");
    }
    
    /**
     * Verifies a password hash against saved hash.
     * 
     * @param passwordHash SHA-256 hash to verify
     * @return true if hash matches saved hash
     * @throws IOException if reading hash fails
     */
    public boolean verifyPasswordHash(String passwordHash) throws IOException {
        if (!Files.exists(SavedStorage.getClientPasswordPath())) {
            return false; // No password set
        }
        
        String storedHash = SavedStorage.readText(SavedStorage.getClientPasswordPath());
        return storedHash.equals(passwordHash);
    }
    
    /**
     * Checks if a password is saved.
     * 
     * @return true if password hash file exists
     */
    public boolean hasPasswordSaved() {
        return Files.exists(SavedStorage.getClientPasswordPath());
    }
    
    /**
     * Gets the saved password hash from disk.
     * 
     * @return SHA-256 password hash
     * @throws IOException if reading fails or no password saved
     */
    public String getSavedPasswordHash() throws IOException {
        if (!hasPasswordSaved()) {
            throw new IOException("No password hash saved");
        }
        return SavedStorage.readText(SavedStorage.getClientPasswordPath());
    }
    
    /**
     * Clears the saved password hash from disk.
     * 
     * @throws IOException if deleting fails
     */
    public void clearPasswordHash() throws IOException {
        if (hasPasswordSaved()) {
            Files.delete(SavedStorage.getClientPasswordPath());
            LOGGER.debug("Deleted saved password hash");
        }
    }
    
    /**
     * Internal class for JSON serialization.
     */
    private static class ServersData {
        public Map<String, String> servers = new HashMap<>();
    }
}
