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

package org.openhitls.crypto.jce.key.generator;

import org.openhitls.crypto.core.SensitiveDataUtil;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SymmetricCipherKeyGenerator extends KeyGeneratorSpi {
    private SecureRandom random;
    private int keySize;

    public SymmetricCipherKeyGenerator() {
        super();
    }

    @Override
    protected void engineInit(SecureRandom random) {
        this.random = random;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("SM4 key generation does not use any parameters");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != 128 && keysize != 192 && keysize != 256) {
            throw new IllegalArgumentException("Invalid key size: " + keysize);
        }
        this.keySize = keysize;
        this.random = random;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (random == null) {
            random = new SecureRandom();
        }

        byte[] keyBytes = new byte[keySize / 8];
        try {
            random.nextBytes(keyBytes);
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            SensitiveDataUtil.clear(keyBytes);
        }
    }
}
