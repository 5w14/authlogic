package net.fivew14.authlogic.verification;

import com.mojang.serialization.Codec;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.util.StringRepresentable;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Enum representing verification payload types.
 * Uses Mojang's Codec API for serialization with dispatch on "type" field.
 */
public enum VerificationPayloadType implements StringRepresentable {
    OFFLINE("authlogic:offline", OfflineVerificationPayload.CODEC),
    ONLINE("authlogic:online", OnlineVerificationPayload.CODEC);

    public static final Codec<VerificationPayloadType> TYPE_CODEC = StringRepresentable.fromEnum(VerificationPayloadType::values);

    private static final Map<String, VerificationPayloadType> BY_NAME = Arrays.stream(values())
            .collect(Collectors.toMap(VerificationPayloadType::getSerializedName, Function.identity()));

    private final String name;
    private final Codec<? extends VerificationPayload> codec;

    VerificationPayloadType(String name, Codec<? extends VerificationPayload> codec) {
        this.name = name;
        this.codec = codec;
    }

    @Override
    public String getSerializedName() {
        return name;
    }

    /**
     * Gets the codec for this payload type.
     *
     * @return Codec for deserializing payloads of this type
     */
    public Codec<? extends VerificationPayload> codec() {
        return codec;
    }

    /**
     * Gets a ResourceLocation for this type.
     *
     * @return ResourceLocation
     */
    public ResourceLocation toResourceLocation() {
        return new ResourceLocation(name);
    }

    /**
     * Looks up a type by its serialized name.
     *
     * @param name Serialized name (e.g., "authlogic:offline")
     * @return Type, or null if not found
     */
    public static VerificationPayloadType byName(String name) {
        return BY_NAME.get(name);
    }

    /**
     * Looks up a type by ResourceLocation.
     *
     * @param location ResourceLocation
     * @return Type, or null if not found
     */
    public static VerificationPayloadType byResourceLocation(ResourceLocation location) {
        return BY_NAME.get(location.toString());
    }
}
