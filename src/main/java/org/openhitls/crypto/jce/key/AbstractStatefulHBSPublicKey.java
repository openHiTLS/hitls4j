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

import java.security.spec.AlgorithmParameterSpec;

import org.openhitls.crypto.jce.interfaces.StatefulHBSPublicKey;

public abstract class AbstractStatefulHBSPublicKey implements StatefulHBSPublicKey {
    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final AlgorithmParameterSpec params;
    private final byte[] encoded;

    protected AbstractStatefulHBSPublicKey(String algorithm, AlgorithmParameterSpec params, byte[] encoded) {
        if (algorithm == null || params == null || encoded == null) {
            throw new NullPointerException("algorithm, params and encoded cannot be null");
        }
        this.algorithm = algorithm;
        this.params = params;
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    @Override
    public byte[] getPublicData() {
        return encoded.clone();
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        return params;
    }
}
