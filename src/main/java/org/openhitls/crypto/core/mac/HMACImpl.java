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

package org.openhitls.crypto.core.mac;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;

public class HMACImpl extends NativeResource {
    public HMACImpl(String algorithm, byte[] key) {
        super(initContext(algorithm, key), CryptoNative::hmacFree);
    }

    private static long initContext(String algorithm, byte[] key) {
        if (algorithm == null) {
            throw new IllegalArgumentException("Algorithm cannot be null");
        }
        return CryptoNative.hmacInit(algorithm, key);
    }

    public void update(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        CryptoNative.hmacUpdate(nativeContext, data, 0, data.length);
    }

    public void update(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("Input data cannot be null");
        }
        if (offset < 0 || length < 0 || offset > data.length || length > data.length - offset) {
            throw new IllegalArgumentException("Invalid offset or length");
        }
        CryptoNative.hmacUpdate(nativeContext, data, offset, length);
    }

    public byte[] doFinal() {
        return CryptoNative.hmacFinal(nativeContext);
    }

    public void reinit() {
        CryptoNative.hmacReinit(nativeContext);
    }

    public int getMacLength() {
        return CryptoNative.hmacGetMacLength(nativeContext);
    }

    // Convenience method to compute HMAC in one call
    public static byte[] compute(String algorithm, byte[] key, byte[] data) {
        try (HMACImpl hmac = new HMACImpl(algorithm, key)) {
            hmac.update(data);
            return hmac.doFinal();
        }
    }
}
