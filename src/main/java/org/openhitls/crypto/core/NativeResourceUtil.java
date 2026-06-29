package org.openhitls.crypto.core;

import java.util.function.Function;

public final class NativeResourceUtil {
    private NativeResourceUtil() {
    }

    public static RuntimeException closeAndCapture(NativeResource resource) {
        if (resource == null) {
            return null;
        }
        try {
            resource.close();
            return null;
        } catch (RuntimeException closeFailure) {
            return closeFailure;
        }
    }

    public static void closeSuppressing(NativeResource resource, Throwable primaryFailure) {
        RuntimeException closeFailure = closeAndCapture(resource);
        if (closeFailure != null) {
            primaryFailure.addSuppressed(closeFailure);
        }
    }

    /**
     * Closes the current resource before publishing a replacement.
     * If closing fails, the replacement remains owned by the caller.
     */
    public static <T extends NativeResource, E extends Exception> T replaceAfterClosing(
            T current, T replacement, Function<RuntimeException, E> exceptionFactory) throws E {
        RuntimeException closeFailure = closeAndCapture(current);
        if (closeFailure != null) {
            throw exceptionFactory.apply(closeFailure);
        }
        return replacement;
    }
}
