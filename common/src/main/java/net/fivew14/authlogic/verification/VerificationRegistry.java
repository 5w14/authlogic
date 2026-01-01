package net.fivew14.authlogic.verification;

import com.mojang.logging.LogUtils;
import net.minecraft.resources.ResourceLocation;
import org.slf4j.Logger;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for verification codecs.
 * Thread-safe registry for VerificationCodec implementations.
 */
public class VerificationRegistry {
    private static final Logger LOGGER = LogUtils.getLogger();
    
    private static final Map<ResourceLocation, VerificationCodec> CODECS = new ConcurrentHashMap<>();
    
    /**
     * Registers a verification codec.
     * 
     * @param type Resource location for this codec
     * @param codec Codec implementation
     * @throws IllegalStateException if type is already registered
     */
    public static void register(ResourceLocation type, VerificationCodec codec) {
        if (CODECS.containsKey(type)) {
            throw new IllegalStateException("Verification codec already registered: " + type);
        }
        CODECS.put(type, codec);
        LOGGER.debug("Registered verification codec: {}", type);
    }
    
    /**
     * Gets a verification codec by type.
     * 
     * @param type Resource location for the codec
     * @return Codec implementation
     * @throws IllegalArgumentException if type is not registered
     */
    public static VerificationCodec get(ResourceLocation type) {
        VerificationCodec codec = CODECS.get(type);
        if (codec == null) {
            throw new IllegalArgumentException("Unknown verification codec: " + type);
        }
        return codec;
    }
    
    /**
     * Gets all registered codec types.
     * 
     * @return Set of registered ResourceLocations
     */
    public static Set<ResourceLocation> getRegisteredTypes() {
        return CODECS.keySet();
    }
    
    /**
     * Checks if a codec type is registered.
     * 
     * @param type Resource location to check
     * @return true if registered
     */
    public static boolean isRegistered(ResourceLocation type) {
        return CODECS.containsKey(type);
    }
}
