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

package org.openhitls.crypto.jce.signer;

import java.security.SignatureException;
import java.util.Arrays;
import org.openhitls.crypto.core.hash.MessageDigestImpl;

final class SignatureDigest {
    private final MessageDigestImpl messageDigest;
    private final String signatureAlgorithm;
    private boolean inputUpdated;

    SignatureDigest(String digestAlgorithm, String signatureAlgorithm) {
        this.messageDigest = new MessageDigestImpl(digestAlgorithm);
        this.signatureAlgorithm = signatureAlgorithm;
    }

    void update(byte[] input, int offset, int length) throws SignatureException {
        SignerBuffer.validateUpdateInput(input, offset, length);
        try {
            messageDigest.update(input, offset, length);
        } catch (RuntimeException e) {
            throw new SignatureException("Failed to update " + signatureAlgorithm + " digest", e);
        }
        inputUpdated = true;
    }

    byte[] finishAndReset() {
        try {
            return messageDigest.doFinalAndReset();
        } finally {
            inputUpdated = false;
        }
    }

    void reset() {
        messageDigest.reset();
        inputUpdated = false;
    }

    boolean hasInput() {
        return inputUpdated;
    }

    static void clear(byte[] digest) {
        if (digest != null) {
            Arrays.fill(digest, (byte) 0);
        }
    }
}
