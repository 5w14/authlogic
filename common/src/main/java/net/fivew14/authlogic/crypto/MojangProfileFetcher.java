package net.fivew14.authlogic.crypto;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.mojang.logging.LogUtils;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Fetches and caches Mojang profile data for UUID-username verification.
 * Uses in-memory cache with TTL to reduce API calls.
 */
public class MojangProfileFetcher {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final String MOJANG_SESSION_URL = "https://sessionserver.mojang.com/session/minecraft/profile/";
    private static final long CACHE_DURATION_MS = TimeUnit.MINUTES.toMillis(60); // 60 minute cache
    private static final Gson GSON = new Gson();

    /**
     * Profile data from Mojang API.
     */
    public record MojangProfile(String id, String name, long fetchedAt) {
        /**
         * Gets the UUID in standard format (with dashes).
         *
         * @return UUID
         */
        public UUID getUUID() {
            // id is 32 hex chars without dashes
            String withDashes = id.substring(0, 8) + "-" +
                    id.substring(8, 12) + "-" +
                    id.substring(12, 16) + "-" +
                    id.substring(16, 20) + "-" +
                    id.substring(20, 32);
            return UUID.fromString(withDashes);
        }

        /**
         * Checks if this cache entry is still valid.
         *
         * @return true if valid
         */
        public boolean isValid() {
            return (System.currentTimeMillis() - fetchedAt) < CACHE_DURATION_MS;
        }
    }

    // Cache: UUID (without dashes) -> profile
    private static final ConcurrentHashMap<String, MojangProfile> profileCache = new ConcurrentHashMap<>();

    /**
     * Gets profile data for a UUID from Mojang API (uses cache if available).
     *
     * @param uuid Player's UUID
     * @return CompletableFuture with Optional profile data (empty if not found or error)
     */
    public static CompletableFuture<Optional<MojangProfile>> getProfileByUUID(UUID uuid) {
        String trimmedUUID = uuid.toString().replace("-", "");

        // Check cache
        MojangProfile cached = profileCache.get(trimmedUUID);
        if (cached != null && cached.isValid()) {
            LOGGER.debug("Using cached profile for UUID {}", uuid);
            return CompletableFuture.completedFuture(Optional.of(cached));
        }

        // Fetch from API
        return CompletableFuture.supplyAsync(() -> {
            try {
                return Optional.of(fetchProfileFromAPI(trimmedUUID));
            } catch (Exception e) {
                LOGGER.error("Failed to fetch profile for UUID {}", uuid, e);
                // Return cached value even if expired, rather than nothing
                if (cached != null) {
                    LOGGER.warn("Returning expired cache for UUID {} due to API failure", uuid);
                    return Optional.of(cached);
                }
                return Optional.empty();
            }
        });
    }

    /**
     * Verifies that a UUID matches a username according to Mojang's records.
     *
     * @param uuid             Player's UUID
     * @param expectedUsername Expected username
     * @return CompletableFuture with true if UUID-username matches, false otherwise
     */
    public static CompletableFuture<Boolean> verifyUUIDMatchesUsername(UUID uuid, String expectedUsername) {
        return getProfileByUUID(uuid).thenApply(profileOpt -> {
            if (profileOpt.isEmpty()) {
                LOGGER.warn("Could not verify UUID {} - profile not found or API error", uuid);
                return false;
            }

            MojangProfile profile = profileOpt.get();
            boolean matches = profile.name.equalsIgnoreCase(expectedUsername);

            if (!matches) {
                LOGGER.warn("UUID-username mismatch for {}: expected '{}', got '{}'",
                        uuid, expectedUsername, profile.name);
            } else {
                LOGGER.debug("UUID-username verified for {} = {}", uuid, profile.name);
            }

            return matches;
        });
    }

    /**
     * Fetches profile data from Mojang API.
     *
     * @param trimmedUUID UUID without dashes
     * @return Profile data
     * @throws Exception if fetch or parsing fails
     */
    private static MojangProfile fetchProfileFromAPI(String trimmedUUID) throws Exception {
        URL url = new URL(MOJANG_SESSION_URL + trimmedUUID);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestProperty("User-Agent", "AuthLogic/1.0");

        int responseCode = conn.getResponseCode();
        if (responseCode == 204 || responseCode == 404) {
            throw new RuntimeException("Profile not found for UUID: " + trimmedUUID);
        }
        if (responseCode != 200) {
            throw new RuntimeException("Mojang API returned status: " + responseCode);
        }

        // Read response
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }

        // Parse JSON response
        JsonObject jsonResponse = GSON.fromJson(response.toString(), JsonObject.class);
        String id = jsonResponse.get("id").getAsString();
        String name = jsonResponse.get("name").getAsString();

        // Cache and return
        MojangProfile profile = new MojangProfile(id, name, System.currentTimeMillis());
        profileCache.put(trimmedUUID, profile);

        LOGGER.debug("Fetched profile for UUID {}: {}", trimmedUUID, name);
        return profile;
    }

    /**
     * Clears the cache.
     */
    public static void clearCache() {
        profileCache.clear();
        LOGGER.debug("Cleared Mojang profile cache");
    }
}
