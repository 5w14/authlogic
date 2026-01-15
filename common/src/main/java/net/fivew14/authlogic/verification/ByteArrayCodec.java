package net.fivew14.authlogic.verification;

import com.mojang.serialization.Codec;
import com.mojang.serialization.DataResult;

import java.util.Base64;

/**
 * Codec for byte arrays, encoding as Base64 strings.
 */
public final class ByteArrayCodec {

    /**
     * Codec instance for byte arrays.
     * Encodes byte[] as Base64 string for JSON/NBT compatibility.
     */
    public static final Codec<byte[]> INSTANCE = Codec.STRING.comapFlatMap(
            str -> {
                try {
                    return DataResult.success(Base64.getDecoder().decode(str));
                } catch (IllegalArgumentException e) {
                    return DataResult.error(() -> "Invalid Base64: " + e.getMessage());
                }
            },
            bytes -> Base64.getEncoder().encodeToString(bytes)
    );

    private ByteArrayCodec() {
    }
}
