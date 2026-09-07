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

import org.openhitls.crypto.core.pqc.StatefulHBSSignResult;
import org.openhitls.crypto.core.pqc.XMSSMTImpl;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPrivateKey;
import org.openhitls.crypto.jce.key.AbstractStatefulHBSPublicKey;
import org.openhitls.crypto.jce.key.XMSSMTPrivateKeyImpl;
import org.openhitls.crypto.jce.key.XMSSMTPublicKeyImpl;

public class XMSSMTSigner extends AbstractStatefulHBSSigner {
    protected String algorithmName() {
        return "XMSSMT";
    }

    protected StatefulHBSSignResult sign(AbstractStatefulHBSPrivateKey privateKey, byte[] privateState, byte[] data) {
        XMSSMTPrivateKeyImpl key = (XMSSMTPrivateKeyImpl) privateKey;
        try (XMSSMTImpl impl = new XMSSMTImpl(key.getParams())) {
            return impl.sign(privateState, data);
        }
    }

    protected boolean verify(AbstractStatefulHBSPublicKey publicKey, byte[] data, byte[] signature) {
        XMSSMTPublicKeyImpl key = (XMSSMTPublicKeyImpl) publicKey;
        try (XMSSMTImpl impl = new XMSSMTImpl(key.getParams())) {
            return impl.verify(key.getEncoded(), data, signature);
        }
    }
}
