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

package org.openhitls.crypto.core.pqc;

import org.openhitls.crypto.core.CryptoNative;
import org.openhitls.crypto.core.NativeResource;
import org.openhitls.crypto.jce.spec.XMSSParameterSpec;

public class XMSSImpl extends NativeResource {
    private final XMSSParameterSpec params;

    public XMSSImpl(XMSSParameterSpec params) {
        super(CryptoNative.xmssCreateContext(params.getName()), CryptoNative::xmssFreeContext);
        this.params = params;
    }

    public byte[][] generateKeyPair() {
        return CryptoNative.xmssGenerateKeyPair(nativeContext);
    }

    public StatefulHBSSignResult sign(byte[] privateKey, byte[] data) {
        CryptoNative.xmssSetPrivateKey(nativeContext, privateKey);
        byte[][] result = CryptoNative.xmssSignAndExportState(nativeContext, data);
        return new StatefulHBSSignResult(result[0], result[1]);
    }

    public boolean verify(byte[] publicKey, byte[] data, byte[] signature) {
        CryptoNative.xmssSetPublicKey(nativeContext, publicKey);
        return CryptoNative.xmssVerify(nativeContext, data, signature);
    }

    public XMSSParameterSpec getParams() {
        return params;
    }
}
