package net.fivew14.authlogic.crypto;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.mojang.logging.LogUtils;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import java.util.concurrent.TimeUnit;

/**
 * Fetches and caches Mojang's public keys for player certificate verification.
 * Uses in-memory cache with 120-minute TTL.
 */
public class MojangPublicKeyFetcher {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final String MOJANG_PUBLIC_KEYS_URL = "https://api.minecraftservices.com/publickeys";

    private static final Gson GSON = new Gson();
    private static final long CACHE_DURATION_MS = TimeUnit.MINUTES.toMillis(120);
    
    private static List<PublicKey> cachedPublicKeys = new ArrayList<>();
    private static long cacheExpiryTime = 0;
    private static CompletableFuture<List<PublicKey>> ongoingFetch = null;

    /**
     * Gets Mojang's public keys, using cache if available.
     * Fetches from API if cache is expired or empty.
     *
     * Cache TTL is fixed at 120 minutes.
     *
     * @return CompletableFuture with list of Mojang public keys
     */
    public static synchronized CompletableFuture<List<PublicKey>> getPublicKeys() {
        // Check if cache is still valid
        long now = System.currentTimeMillis();
        if (!cachedPublicKeys.isEmpty() && now < cacheExpiryTime) {
            long remainingMinutes = (cacheExpiryTime - now) / 60000;
            LOGGER.debug("Using cached Mojang public keys ({} keys, expires in {} min)", 
                cachedPublicKeys.size(), remainingMinutes);
            return CompletableFuture.completedFuture(new ArrayList<>(cachedPublicKeys));
        }
        
        // If there's already an ongoing fetch, return that future
        if (ongoingFetch != null && !ongoingFetch.isDone()) {
            LOGGER.debug("Mojang public keys fetch already in progress");
            return ongoingFetch;
        }
        
        // Start new fetch
        LOGGER.debug("Fetching Mojang public keys from API");
        ongoingFetch = CompletableFuture.supplyAsync(() -> {
            try {
                return fetchPublicKeysFromAPI();
            } catch (Exception e) {
                LOGGER.error("Failed to fetch Mojang public keys", e);
                // Return cached keys if available, even if expired
                if (!cachedPublicKeys.isEmpty()) {
                    LOGGER.warn("Using expired cache due to fetch failure");
                    return new ArrayList<>(cachedPublicKeys);
                }
                throw new RuntimeException("Failed to fetch Mojang public keys and no cache available", e);
            }
        });
        
        return ongoingFetch;
    }
    
    /**
     * Fetches public keys from Mojang API.
     * 
     * @return List of RSA public keys
     * @throws Exception if fetch or parsing fails
     */
    private static List<PublicKey> fetchPublicKeysFromAPI() throws Exception {
        URL url = new URL(MOJANG_PUBLIC_KEYS_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestProperty("User-Agent", "AuthLogic/1.0");
        
        int responseCode = conn.getResponseCode();
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
        JsonArray keysArray = jsonResponse.getAsJsonArray("playerCertificateKeys");
        
        List<PublicKey> keys = new ArrayList<>();
        for (int i = 0; i < keysArray.size(); i++) {
            JsonObject keyObj = keysArray.get(i).getAsJsonObject();
            String publicKeyPem = keyObj.get("publicKey").getAsString();
            
            // Convert PEM to PublicKey
            PublicKey publicKey = pemToPublicKey(publicKeyPem);
            keys.add(publicKey);
        }
        
        // Update cache
        cachedPublicKeys = new ArrayList<>(keys);
        cacheExpiryTime = System.currentTimeMillis() + CACHE_DURATION_MS;
        
        LOGGER.debug("Successfully fetched {} Mojang public keys (cache expires in {} min)", 
            keys.size(), CACHE_DURATION_MS / 60000);
        return keys;
    }
    
    /**
     * Converts PEM-formatted public key to PublicKey object.
     * 
     * @param pem PEM string (base64 without headers)
     * @return RSA PublicKey
     * @throws Exception if conversion fails
     */
    private static PublicKey pemToPublicKey(String pem) throws Exception {
        // Remove PEM headers/footers if present and whitespace
        String publicKeyPEM = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        
        // Decode base64
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        
        // Generate RSA public key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Clears the cache, forcing a fresh fetch on next request.
     */
    public static synchronized void clearCache() {
        cachedPublicKeys.clear();
        cacheExpiryTime = 0;
        LOGGER.debug("Cleared Mojang public keys cache");
    }
}
