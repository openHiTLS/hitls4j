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

package org.openhitls.crypto.core.hash;

import java.util.Arrays;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class MessageDigestImpl extends NativeResource {
    private final String algorithm;

    public MessageDigestImpl(String algorithm) {
        super(initContext(algorithm), CryptoNative::messageDigestFree);
        this.algorithm = algorithm;
    }

    private static long initContext(String algorithm) {
        return CryptoNative.messageDigestInit(algorithm);
    }

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        CryptoNative.messageDigestUpdate(nativeContext, data, 0, data.length);
    }

    public void update(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (offset < 0 || length < 0 || length > data.length - offset) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        CryptoNative.messageDigestUpdate(nativeContext, data, offset, length);
    }

    public byte[] doFinal() {
        return CryptoNative.messageDigestFinal(nativeContext);
    }

    /**
     * Finishes the current digest and restores this context for the next message.
     */
    public byte[] doFinalAndReset() {
        byte[] digest = null;
        Throwable primaryFailure = null;
        try {
            digest = doFinal();
            return digest;
        } catch (RuntimeException | Error e) {
            primaryFailure = e;
            throw e;
        } finally {
            try {
                reset();
            } catch (RuntimeException | Error resetFailure) {
                if (primaryFailure != null) {
                    primaryFailure.addSuppressed(resetFailure);
                } else {
                    if (digest != null) {
                        Arrays.fill(digest, (byte) 0);
                    }
                    throw resetFailure;
                }
            }
        }
    }

    public void reset() {
        CryptoNative.messageDigestReset(nativeContext);
    }

    public byte[] digest(byte[] data) {
        update(data);
        return doFinal();
    }

    public static byte[] hash(String algorithm, byte[] data) {
        try (MessageDigestImpl md = new MessageDigestImpl(algorithm)) {
            return md.digest(data);
        }
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
