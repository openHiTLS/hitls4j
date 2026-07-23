package org.openhitls.crypto.jce.signer;

import java.security.InvalidKeyException;
import java.security.SignatureException;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.core.NativeResourceUtil;

final class SignatureState {
    private boolean initialized;
    private boolean forSigning;

    void activateSigning() {
        initialized = true;
        forSigning = true;
    }

    void activateSigning(Runnable clearInput) {
        clearInput.run();
        activateSigning();
    }

    void activateVerification() {
        initialized = true;
        forSigning = false;
    }

    void activateVerification(Runnable clearInput) {
        clearInput.run();
        activateVerification();
    }

    boolean isInitialized() {
        return initialized;
    }

    void ensureReadyForUpdate(String algorithm) throws SignatureException {
        if (!initialized) {
            throw new SignatureException(algorithm + " signature not initialized");
        }
    }

    void ensureSigning(String algorithm) throws SignatureException {
        if (!initialized || !forSigning) {
            throw new SignatureException(algorithm + " signature not initialized for signing");
        }
    }

    void ensureVerification(String algorithm) throws SignatureException {
        if (!initialized || forSigning) {
            throw new SignatureException(algorithm + " signature not initialized for verification");
        }
    }

    static <T extends NativeResource> T replaceAfterReset(
            T current, T replacement, Runnable resetInput, String algorithm)
            throws InvalidKeyException {
        resetInput.run();
        return NativeResourceUtil.replaceAfterClosing(current, replacement,
                failure -> new InvalidKeyException(
                        "Failed to close previous " + algorithm + " context", failure));
    }
}
