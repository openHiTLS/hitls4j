/*
 * Copyright (c) 2026 openHiTLS. All Rights Reserved.
 *
 * hitls4j is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

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
