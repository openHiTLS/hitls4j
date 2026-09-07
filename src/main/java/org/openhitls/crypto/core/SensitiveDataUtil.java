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

package org.openhitls.crypto.core;

import java.util.Arrays;

public final class SensitiveDataUtil {
    private SensitiveDataUtil() {
    }

    public static void clear(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    public static byte[] copy(byte[] value) {
        return value != null ? value.clone() : null;
    }

    public static KeyMaterial copyKeyMaterial(byte[] publicKey, byte[] privateKey) {
        return new KeyMaterial(copy(publicKey), copy(privateKey));
    }

    public static final class KeyMaterial {
        private final byte[] publicKey;
        private final byte[] privateKey;

        private KeyMaterial(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public byte[] publicKey() {
            return publicKey;
        }

        public byte[] privateKey() {
            return privateKey;
        }

        public void clearPrivate() {
            clear(privateKey);
        }
    }
}
