package net.fivew14.authlogic.server;

import com.mojang.logging.LogUtils;
import net.fivew14.authlogic.server.state.CommonAuthState;
import net.fivew14.authlogic.server.state.InProgressAuthState;
import org.slf4j.Logger;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages authentication states for all active connections.
 * Uses thread-safe map for concurrent access.
 * 
 * States are keyed by the server nonce, which is a cryptographically random
 * 64-bit value generated for each authentication challenge. This ensures
 * reliable correlation between challenges and responses at the protocol level,
 * independent of transport-layer connection identifiers.
 */
public class ServerAuthState {
    private static final Logger LOGGER = LogUtils.getLogger();
    
    /**
     * Timeout for in-progress auth states in milliseconds.
     * Auth states older than this will be cleaned up.
     */
    private static final long AUTH_STATE_TIMEOUT_MS = 30_000; // 30 seconds
    
    /**
     * Timeout for authenticated player entries in milliseconds.
     * If a player authenticates but doesn't join within this time, the entry is removed.
     */
    private static final long AUTHENTICATED_PLAYER_TIMEOUT_MS = 60_000; // 60 seconds
    
    /**
     * Map of server nonce -> auth state.
     * Using Long (server nonce) as key ensures protocol-level correlation.
     */
    public static final Map<Long, CommonAuthState> STATE = new ConcurrentHashMap<>();
    
    /**
     * Record to track authenticated player with timestamp.
     */
    private record AuthenticatedPlayer(String username, long authenticatedAt) {}
    
    /**
     * Map of player usernames -> authentication info.
     * This is used to verify that a player completed authentication before joining.
     * Entries are removed after the player join check completes or after timeout.
     * 
     * Username is used instead of UUID because UUIDs are not reliable in offline mode.
     */
    private static final Map<String, AuthenticatedPlayer> AUTHENTICATED_PLAYERS = new ConcurrentHashMap<>();

    /**
     * Creates a new InProgressAuthState for a connection.
     * 
     * @return New in-progress auth state
     */
    public static InProgressAuthState newAuthState() {
        return new InProgressAuthState();
    }
    
    /**
     * Removes an auth state by its server nonce.
     * Should be called after authentication completes or times out.
     * 
     * @param serverNonce The server nonce to remove
     * @return The removed state, or null if not found
     */
    public static CommonAuthState remove(long serverNonce) {
        return STATE.remove(serverNonce);
    }
    
    /**
     * Checks if a state exists for the given server nonce.
     * 
     * @param serverNonce The server nonce to check
     * @return true if state exists
     */
    public static boolean exists(long serverNonce) {
        return STATE.containsKey(serverNonce);
    }
    
    /**
     * Marks a player as authenticated.
     * Called after successful authentication during login.
     * 
     * @param username The authenticated player's username
     */
    public static void markAuthenticated(String username) {
        LOGGER.info("Marking player '{}' as authenticated", username);
        AUTHENTICATED_PLAYERS.put(username, new AuthenticatedPlayer(username, System.currentTimeMillis()));
        LOGGER.debug("AUTHENTICATED_PLAYERS now contains {} entries", AUTHENTICATED_PLAYERS.size());
    }
    
    /**
     * Checks if a player was authenticated and consumes the authentication.
     * This should be called when a player joins to verify they completed authentication.
     * The authentication status is consumed (removed) after checking.
     * 
     * @param username The player's username to check
     * @return true if the player was authenticated, false otherwise
     */
    public static boolean consumeAuthentication(String username) {
        LOGGER.debug("Consuming authentication for '{}', current entries: {}", username, AUTHENTICATED_PLAYERS.keySet());
        boolean result = AUTHENTICATED_PLAYERS.remove(username) != null;
        LOGGER.info("consumeAuthentication('{}') = {}", username, result);
        return result;
    }
    
    /**
     * Checks if a player is authenticated without consuming the status.
     * 
     * @param username The player's username to check
     * @return true if the player is authenticated
     */
    public static boolean isAuthenticated(String username) {
        return AUTHENTICATED_PLAYERS.containsKey(username);
    }
    
    /**
     * Cleans up stale authentication states and authenticated player entries.
     * Should be called periodically (e.g., on server tick).
     */
    public static void cleanupStaleEntries() {
        long now = System.currentTimeMillis();
        
        // Cleanup stale auth states
        Iterator<Map.Entry<Long, CommonAuthState>> stateIterator = STATE.entrySet().iterator();
        while (stateIterator.hasNext()) {
            Map.Entry<Long, CommonAuthState> entry = stateIterator.next();
            CommonAuthState state = entry.getValue();
            
            // Only clean up in-progress states (not finished ones which may be needed for reference)
            if (!state.isFinished() && (now - state.createdAt) > AUTH_STATE_TIMEOUT_MS) {
                stateIterator.remove();
                LOGGER.debug("Cleaned up stale auth state for nonce {}", entry.getKey());
            }
        }
        
        // Cleanup stale authenticated player entries
        Iterator<Map.Entry<String, AuthenticatedPlayer>> playerIterator = AUTHENTICATED_PLAYERS.entrySet().iterator();
        while (playerIterator.hasNext()) {
            Map.Entry<String, AuthenticatedPlayer> entry = playerIterator.next();
            AuthenticatedPlayer player = entry.getValue();
            
            if ((now - player.authenticatedAt()) > AUTHENTICATED_PLAYER_TIMEOUT_MS) {
                playerIterator.remove();
                LOGGER.debug("Cleaned up stale authenticated player entry for {}", player.username());
            }
        }
    }
    
    /**
     * Gets the current count of pending auth states (for monitoring/debugging).
     * 
     * @return Number of entries in the STATE map
     */
    public static int getAuthStateCount() {
        return STATE.size();
    }
    
    /**
     * Gets the current count of authenticated players waiting to join (for monitoring/debugging).
     * 
     * @return Number of entries in the AUTHENTICATED_PLAYERS map
     */
    public static int getAuthenticatedPlayersCount() {
        return AUTHENTICATED_PLAYERS.size();
    }
}
