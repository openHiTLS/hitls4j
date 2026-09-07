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

package org.openhitls.crypto.jce.key.factory;

import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.LMSPublicKeyImpl;
import org.openhitls.crypto.jce.spec.LMSPublicKeySpec;
import org.openhitls.crypto.jce.spec.StatefulHBSPublicKeySpec;

public class LMSKeyFactory extends AbstractPublicOnlyStatefulHBSKeyFactory {
    @Override
    protected PublicKey createPublic(StatefulHBSPublicKeySpec spec) {
        LMSPublicKeySpec lmsSpec = (LMSPublicKeySpec) spec;
        return new LMSPublicKeyImpl(lmsSpec.getParams(), lmsSpec.getEncoded());
    }

    @Override
    protected boolean isPublicSpec(KeySpec spec) {
        return spec instanceof LMSPublicKeySpec;
    }

    @Override
    protected StatefulHBSPublicKeySpec toPublicSpec(AbstractStatefulHBSPublicKey key)
            throws InvalidKeySpecException {
        if (!(key instanceof LMSPublicKeyImpl)) {
            throw new InvalidKeySpecException("Not an LMS public key");
        }
        LMSPublicKeyImpl lmsKey = (LMSPublicKeyImpl) key;
        return new LMSPublicKeySpec(lmsKey.getEncoded(), lmsKey.getParams());
    }
}
