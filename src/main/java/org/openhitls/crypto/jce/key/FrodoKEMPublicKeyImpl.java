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

import org.openhitls.crypto.jce.interfaces.FrodoKEMPublicKey;
import org.openhitls.crypto.jce.spec.FrodoKEMParameterSpec;

public class FrodoKEMPublicKeyImpl implements FrodoKEMPublicKey {
    private static final long serialVersionUID = 1L;
    private final FrodoKEMParameterSpec params;
    private final byte[] encoded;

    public FrodoKEMPublicKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
    }

    public FrodoKEMPublicKeyImpl(FrodoKEMParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
    }

    @Override
    public byte[] getPublicData() {
        return encoded != null ? encoded.clone() : null;
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
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public FrodoKEMParameterSpec getParams() {
        return params;
    }
}
