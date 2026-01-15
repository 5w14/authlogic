package net.fivew14.authlogic.client;

import com.mojang.logging.LogUtils;
import net.fivew14.authlogic.verification.VerificationException;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.function.Supplier;

/**
 * Handler for client-side authentication operations.
 * Manages password retrieval and authentication flow.
 */
public class ClientAuthHandler {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static ClientStorage storage;
    private static PasswordProvider passwordProvider;

    /**
     * Sets the client storage instance.
     *
     * @param clientStorage Client storage instance
     */
    public static void setStorage(ClientStorage clientStorage) {
        storage = clientStorage;
    }

    /**
     * Sets the password provider for retrieving passwords.
     *
     * @param provider Password provider implementation
     */
    public static void setPasswordProvider(PasswordProvider provider) {
        passwordProvider = provider;
    }

    /**
     * Gets the client storage instance.
     *
     * @return Client storage
     * @throws IllegalStateException if storage not initialized
     */
    private static ClientStorage getStorage() {
        if (storage == null) {
            throw new IllegalStateException("ClientStorage not initialized. Call setStorage() first.");
        }
        return storage;
    }

    /**
     * Retrieves password hash for authentication.
     * First checks if saved password exists, otherwise prompts user.
     *
     * @param serverAddress Server being connected to
     * @return SHA-256 password hash
     * @throws VerificationException if password cannot be obtained
     */
    public static String getPasswordHash(String serverAddress) throws VerificationException {
        try {
            // Check if password is saved
            if (getStorage().hasPasswordSaved()) {
                String savedHash = getStorage().getSavedPasswordHash();
                LOGGER.debug("Using saved password hash");
                return savedHash;
            }

            // No saved password - prompt user
            if (passwordProvider == null) {
                throw new VerificationException(
                        "No password provider configured. Cannot authenticate to server."
                );
            }

            String plainPassword = passwordProvider.getPassword(serverAddress);
            if (plainPassword == null || plainPassword.isEmpty()) {
                throw new VerificationException("Password required for authentication");
            }

            // Hash the password immediately
            String passwordHash = ClientStorage.hashPassword(plainPassword);

            // Optionally save for next time (can be made configurable)
            if (passwordProvider.shouldSavePassword()) {
                getStorage().savePasswordHashToDisk(passwordHash);
                getStorage().save();
                LOGGER.debug("Saved password hash for future logins");
            }

            return passwordHash;

        } catch (IOException e) {
            throw new VerificationException("Failed to access password storage", e);
        }
    }

    /**
     * Clears saved password hash from disk.
     *
     * @throws IOException if clearing fails
     */
    public static void clearSavedPassword() throws IOException {
        getStorage().clearPasswordHash();
        getStorage().save();
        LOGGER.debug("Cleared saved password hash");
    }

    /**
     * Interface for providing passwords to the authentication system.
     * Implementations might show a GUI screen, read from config, etc.
     */
    @FunctionalInterface
    public interface PasswordProvider {
        /**
         * Gets the password for authentication.
         *
         * @param serverAddress Server being connected to
         * @return Plain text password (will be hashed immediately)
         */
        String getPassword(String serverAddress);

        /**
         * Whether to save the password hash for future logins.
         *
         * @return true to save password hash
         */
        default boolean shouldSavePassword() {
            return false; // Default: don't save
        }
    }

    /**
     * Password provider that reads from environment variable.
     * For configuration-based deployments.
     */
    public static class EnvironmentPasswordProvider implements PasswordProvider {
        private final String envVarName;
        private final boolean savePassword;

        public EnvironmentPasswordProvider(String envVarName, boolean savePassword) {
            this.envVarName = envVarName;
            this.savePassword = savePassword;
        }

        public EnvironmentPasswordProvider() {
            this("AUTHLOGIC_PASSWORD", false);
        }

        @Override
        public String getPassword(String serverAddress) {
            String password = System.getenv(envVarName);
            if (password == null) {
                LOGGER.warn("Environment variable {} not set", envVarName);
                return null;
            }
            return password;
        }

        @Override
        public boolean shouldSavePassword() {
            return savePassword;
        }
    }

    /**
     * Password provider with a hardcoded constant password.
     * FOR TESTING/DEVELOPMENT ONLY - DO NOT USE IN PRODUCTION!
     */
    public static class ConstantPasswordProvider implements PasswordProvider {
        private final String password;
        private final boolean savePassword;

        /**
         * Creates a constant password provider.
         *
         * @param password     The hardcoded password
         * @param savePassword Whether to save the hash
         */
        public ConstantPasswordProvider(String password, boolean savePassword) {
            this.password = password;
            this.savePassword = savePassword;
            LOGGER.warn("Using ConstantPasswordProvider with hardcoded password - FOR TESTING ONLY!");
        }

        /**
         * Creates a constant password provider with default test password "test123".
         * Auto-saves password hash for convenience.
         */
        public ConstantPasswordProvider() {
            this("test126", true);
        }

        @Override
        public String getPassword(String serverAddress) {
            LOGGER.debug("Using constant test password for server: {}", serverAddress);
            return password;
        }

        @Override
        public boolean shouldSavePassword() {
            return savePassword;
        }
    }

    /**
     * Simple password provider that uses a supplier function.
     * For flexible configuration-based setups.
     */
    public static class SupplierPasswordProvider implements PasswordProvider {
        private final Supplier<String> passwordSupplier;
        private final boolean savePassword;

        public SupplierPasswordProvider(Supplier<String> passwordSupplier, boolean savePassword) {
            this.passwordSupplier = passwordSupplier;
            this.savePassword = savePassword;
        }

        @Override
        public String getPassword(String serverAddress) {
            return passwordSupplier.get();
        }

        @Override
        public boolean shouldSavePassword() {
            return savePassword;
        }
    }
}
