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

package org.openhitls.crypto.jce.key;

import java.security.Key;

public class FrodoKEMCiphertextKey implements Key {
    private final byte[] ciphertext;

    public FrodoKEMCiphertextKey(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("Ciphertext cannot be null");
        }
        this.ciphertext = ciphertext.clone();
    }

    @Override
    public String getAlgorithm() {
        return "FrodoKEM";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return ciphertext != null ? ciphertext.clone() : null;
    }
}
