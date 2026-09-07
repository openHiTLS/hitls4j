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

import org.openhitls.crypto.jce.interfaces.SLHDSAPublicKey;
import org.openhitls.crypto.jce.spec.SLHDSAParameterSpec;

public class SLHDSAPublicKeyImpl implements SLHDSAPublicKey{
    private static final long serialVersionUID = 1L;
    private final SLHDSAParameterSpec params;
    private final byte[] encoded;
    private final byte[] publicKeyData; // raw public key data, not support yet

    public SLHDSAPublicKeyImpl(byte[] encoded) {
        this.encoded = encoded != null ? encoded.clone() : null;
        this.params = null;
        this.publicKeyData = null;
    }

    public SLHDSAPublicKeyImpl(SLHDSAParameterSpec params, byte[] encoded) {
        this.params = params;
        this.encoded = encoded != null ? encoded.clone() : null;
        this.publicKeyData = null;
    }

    @Override
    public SLHDSAParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "SLH-DSA";
    }

    @Override
    public byte[] getEncoded() {
        return encoded != null ? encoded.clone() : null;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getPublicData() {
        return encoded != null ? encoded.clone() : null;
    }
    
}
