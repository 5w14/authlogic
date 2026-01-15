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
 * <p>
 * Storage locations:
 * - Root authlogic/ directory (key files):
 *   - server_private_key.txt: Server's private key
 *   - server_storage.json: Registered player public keys
 *   - client_password.txt: Client's hashed password
 *   - client_servers.json: Trusted server list
 * - Config authlogic/ directory (configuration):
 *   - server_whitelist.json: Whitelist integration
 */
public class SavedStorage {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String CONFIG_DIR = "config/authlogic";
    private static final String ROOT_DIR = "authlogic";

    private static boolean hasMigrated = false;

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
     * Gets the root authlogic directory path.
     * Creates the directory if it doesn't exist.
     *
     * @return Path to authlogic/
     */
    public static Path getRootDir() {
        Path dir = Paths.get(ROOT_DIR);
        try {
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to create root authlogic directory", e);
        }
        return dir;
    }

    /**
     * Migrates files from config/authlogic/ to root authlogic/ directory.
     * Only migrates if the file doesn't already exist in the root directory.
     */
    public static void migrateFilesFromConfig() {
        if (hasMigrated) {
            return;
        }

        migrateFile(getConfigDir().resolve("server_private_key.txt"), getRootDir().resolve("server_private_key.txt"));
        migrateFile(getConfigDir().resolve("server_storage.json"), getRootDir().resolve("server_storage.json"));
        migrateFile(getConfigDir().resolve("client_password.txt"), getRootDir().resolve("client_password.txt"));
        migrateFile(getConfigDir().resolve("client_servers.json"), getRootDir().resolve("client_servers.json"));

        hasMigrated = true;
    }

    private static void migrateFile(Path oldPath, Path newPath) {
        try {
            if (Files.exists(oldPath) && !Files.exists(newPath)) {
                Files.copy(oldPath, newPath);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to migrate file from " + oldPath + " to " + newPath, e);
        }
    }

    /**
     * Gets path to server storage file.
     *
     * @return Path to authlogic/server_storage.json
     */
    public static Path getServerStoragePath() {
        return getRootDir().resolve("server_storage.json");
    }

    /**
     * Gets path to server private key file.
     *
     * @return Path to authlogic/server_private_key.txt
     */
    public static Path getServerPrivateKeyPath() {
        return getRootDir().resolve("server_private_key.txt");
    }

    /**
     * Gets path to client password file.
     *
     * @return Path to authlogic/client_password.txt
     */
    public static Path getClientPasswordPath() {
        return getRootDir().resolve("client_password.txt");
    }

    /**
     * Gets path to client servers file.
     *
     * @return Path to authlogic/client_servers.json
     */
    public static Path getClientServersPath() {
        return getRootDir().resolve("client_servers.json");
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
     * @param path  File path
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
     * @param path   File path
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
     * @param path    File path
     * @param content Content to write
     * @throws IOException if write fails
     */
    public static void writeText(Path path, String content) throws IOException {
        Files.writeString(path, content, StandardCharsets.UTF_8);
    }
}
