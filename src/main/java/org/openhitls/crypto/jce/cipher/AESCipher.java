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

package org.openhitls.crypto.jce.cipher;

import java.security.InvalidKeyException;

public class AESCipher extends AbstractBlockCipher {
    
    @Override
    public String getAlgorithmName() {
        return "AES";
    }
    
    @Override
    public void validateKeySize(byte[] keyBytes) throws InvalidKeyException {
        if (keyBytes == null || (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)) {
            throw new InvalidKeyException("Key must be 16, 24 or 32 bytes");
        }
    }
    
    @Override
    public String[] getSupportedModes() {
        return new String[]{"ECB", "CBC", "CTR", "GCM"};
    }
}
