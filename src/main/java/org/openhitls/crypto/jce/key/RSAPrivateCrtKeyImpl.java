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

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

public class RSAPrivateCrtKeyImpl extends RSAPrivateKeyImpl implements RSAPrivateCrtKey {
    private static final long serialVersionUID = 1234568L;

    public RSAPrivateCrtKeyImpl(byte[] privateExponent, byte[] modulus, BigInteger publicExponent,
            byte[] primeP, byte[] primeQ, byte[] primeExponentP, byte[] primeExponentQ, byte[] crtCoefficient) {
        super(privateExponent, modulus, publicExponent,
                primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
    }

    public RSAPrivateCrtKeyImpl(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent,
            BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ,
            BigInteger crtCoefficient) {
        super(modulus, privateExponent, publicExponent,
                primeP, primeQ, primeExponentP, primeExponentQ, crtCoefficient);
    }

    @Override
    public BigInteger getPrimeP() {
        return primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        return primeQ;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        return primeExponentP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        return primeExponentQ;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        return crtCoefficient;
    }
}
