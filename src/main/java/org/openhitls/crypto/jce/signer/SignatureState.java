package org.openhitls.crypto.jce.signer;

import java.security.SignatureException;

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
}
