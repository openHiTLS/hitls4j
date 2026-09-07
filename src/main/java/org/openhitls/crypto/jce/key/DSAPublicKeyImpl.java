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

import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.math.BigInteger;

public class DSAPublicKeyImpl implements DSAPublicKey {
    private static final long serialVersionUID = 1L;
    private final DSAParameterSpec params;
    private final BigInteger y; // public key value

    public DSAPublicKeyImpl(DSAParameterSpec params, byte[] yBytes) {
        this.params = params;
        this.y = new BigInteger(1, yBytes); // Use 1 as signum for positive value
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public DSAParams getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        // For now, return null as we don't need ASN.1 encoding for our tests
        return null;
    }
} 
