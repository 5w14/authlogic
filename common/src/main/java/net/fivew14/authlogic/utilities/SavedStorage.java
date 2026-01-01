package net.fivew14.authlogic.utilities;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Utility class for file-based storage operations.
 * Handles JSON and text file I/O for authentication data.
 * 
 * Storage locations:
 * - Server: config/authlogic/server_storage.json (player keys)
 * - Server: config/authlogic/server_private_key.txt (server private key)
 * - Client: config/authlogic/client_password.txt (password hash)
 * - Client: config/authlogic/client_servers.json (trusted servers)
 */
public class SavedStorage {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String CONFIG_DIR = "config/authlogic";
    
    /**
     * Gets the config directory path.
     * Creates the directory if it doesn't exist.
     * 
     * @return Path to config/authlogic/
     */
    public static Path getConfigDir() {
        Path dir = Paths.get(CONFIG_DIR);
        try {
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to create config directory", e);
        }
        return dir;
    }
    
    /**
     * Gets path to server storage file.
     * 
     * @return Path to server_storage.json
     */
    public static Path getServerStoragePath() {
        return getConfigDir().resolve("server_storage.json");
    }
    
    /**
     * Gets path to server private key file.
     * 
     * @return Path to server_private_key.txt
     */
    public static Path getServerPrivateKeyPath() {
        return getConfigDir().resolve("server_private_key.txt");
    }
    
    /**
     * Gets path to client password file.
     * 
     * @return Path to client_password.txt
     */
    public static Path getClientPasswordPath() {
        return getConfigDir().resolve("client_password.txt");
    }
    
    /**
     * Gets path to client servers file.
     * 
     * @return Path to client_servers.json
     */
    public static Path getClientServersPath() {
        return getConfigDir().resolve("client_servers.json");
    }
    
    /**
     * Gets path to server whitelist file.
     * 
     * @return Path to server_whitelist.json
     */
    public static Path getServerWhitelistPath() {
        return getConfigDir().resolve("server_whitelist.json");
    }
    
    /**
     * Reads JSON from a file.
     * 
     * @param path File path
     * @param clazz Class to deserialize to
     * @return Deserialized object
     * @throws IOException if file doesn't exist or read fails
     */
    public static <T> T readJson(Path path, Class<T> clazz) throws IOException {
        if (!Files.exists(path)) {
            throw new IOException("File does not exist: " + path);
        }
        String json = Files.readString(path, StandardCharsets.UTF_8);
        return GSON.fromJson(json, clazz);
    }
    
    /**
     * Writes JSON to a file.
     * 
     * @param path File path
     * @param object Object to serialize
     * @throws IOException if write fails
     */
    public static <T> void writeJson(Path path, T object) throws IOException {
        String json = GSON.toJson(object);
        Files.writeString(path, json, StandardCharsets.UTF_8);
    }
    
    /**
     * Reads text from a file.
     * 
     * @param path File path
     * @return File contents as string
     * @throws IOException if file doesn't exist or read fails
     */
    public static String readText(Path path) throws IOException {
        if (!Files.exists(path)) {
            throw new IOException("File does not exist: " + path);
        }
        return Files.readString(path, StandardCharsets.UTF_8).trim();
    }
    
    /**
     * Writes text to a file.
     * 
     * @param path File path
     * @param content Content to write
     * @throws IOException if write fails
     */
    public static void writeText(Path path, String content) throws IOException {
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }
}
