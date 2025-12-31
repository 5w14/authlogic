package net.fivew14.authlogic.verification;

import net.minecraft.network.chat.Component;

/**
 * Exception thrown when verification fails.
 * Verification failures trigger immediate disconnection.
 */
public class VerificationException extends Exception {
    protected Component visualError;

    public VerificationException(String message, Component component) {
        super(message);
        this.visualError = component;
    }

    public VerificationException(String message) {
        this(message, Component.literal(message));
    }

    public VerificationException(Component message) {
        this(message.getString(), message);
    }

    public Component getVisualError() {
        return visualError;
    }

    public VerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
